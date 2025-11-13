package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/scs/redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gomodule/redigo/redis"
	"github.com/pquerna/otp/totp"

	"dystopian.earth/internal/config"
	"dystopian.earth/internal/email"
	"dystopian.earth/internal/markdown"
	"dystopian.earth/internal/secure"
	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Server holds the HTTP server state.
type Server struct {
	cfg       config.Config
	db        *sql.DB
	sessions  *scs.SessionManager
	templates Templates
	renderer  markdown.Renderer
	contentFS fs.FS
	redisPool *redis.Pool
	inviteJWT *inviteTokenManager
	mailer    *email.Service
	cipher    *secure.Cipher
}

var paymentProviderOptions = []string{"Stripe", "Venmo", "PayPal", "Bitcoin"}

var supportedPaymentProviders = map[string]string{
	"stripe":  "Stripe",
	"venmo":   "Venmo",
	"paypal":  "PayPal",
	"bitcoin": "Bitcoin",
	"btc":     "Bitcoin",
}

// New creates a new server instance.
func New(cfg config.Config, db *sql.DB, templates Templates) (*Server, error) {
	pool := &redis.Pool{
		MaxIdle:     5,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			options := []redis.DialOption{}
			if cfg.RedisPassword != "" {
				options = append(options, redis.DialPassword(cfg.RedisPassword))
			}
			return redis.Dial("tcp", cfg.RedisAddr, options...)
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
	}

	store := redisstore.New(pool)

	session := scs.New()
	session.Store = store
	session.Cookie.Name = "portal_session"
	session.Cookie.HttpOnly = true
	session.Cookie.SameSite = http.SameSiteLaxMode
	session.Lifetime = cfg.SessionTTL

	renderer := markdown.New()
	content := os.DirFS(cfg.ContentDir)

	tokens, err := newInviteTokenManager(5 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("init invite tokens: %w", err)
	}

	var cipher *secure.Cipher
	if len(cfg.EncryptionKey) == 32 {
		c, err := secure.NewCipher(cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("init cipher: %w", err)
		}
		cipher = c
	}

	mailer := email.New(email.Config{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Token:    cfg.SMTPToken,
		UseTLS:   cfg.SMTPUseTLS,
		From:     cfg.EmailFrom,
		Queue:    64,
	})

	return &Server{
		cfg:       cfg,
		db:        db,
		sessions:  session,
		templates: templates,
		renderer:  renderer,
		contentFS: content,
		redisPool: pool,
		inviteJWT: tokens,
		mailer:    mailer,
		cipher:    cipher,
	}, nil
}

// Routes returns the configured router.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(s.sessions.LoadAndSave)
	r.Use(s.postShield)

	fileServer := http.FileServer(http.Dir(s.cfg.StaticDir))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	r.Get("/", s.handlePage("index"))
	r.Get("/pages/{slug}", s.pageHandler)
	r.Get("/challenges", s.challenges)

	r.Get("/login", s.getLogin)
	r.Post("/login", s.postLogin)
	r.Get("/logout", s.requireAuth(s.getLogout))

	r.Get("/join", s.getJoin)
	r.Post("/join", s.postJoin)
	r.Post("/join/flag", s.postJoinFlag)

	r.Get("/register", s.getJoin)
	r.Post("/register", s.postJoin)

	r.Group(func(protected chi.Router) {
		protected.Use(s.authMiddleware)
		protected.Get("/dashboard", s.dashboard)
		protected.Post("/profile", s.updateProfile)
		protected.Post("/profile/email", s.requestEmailChange)
		protected.Post("/profile/otp", s.updateOTP)
		protected.Post("/profile/ldap", s.updateLDAP)
		protected.Post("/profile/wireguard", s.generateWireguard)
		protected.Post("/payment", s.updatePayment)
		protected.Post("/invites", s.createMemberInvite)
	})

	r.Get("/email/confirm", s.confirmEmailChange)

	r.Group(func(admin chi.Router) {
		admin.Use(s.authMiddleware)
		admin.Use(s.requireAdmin)
		admin.Get("/admin", s.adminDashboard)
		admin.Post("/admin/email/test", s.adminSendTestEmail)
		admin.Get("/admin/users/{id}", s.adminViewUser)
		admin.Post("/admin/users/{id}/update", s.adminUpdateUser)
		admin.Post("/admin/users/{id}/promote", s.adminPromoteUser)
		admin.Post("/admin/users/{id}/toggle-disable", s.adminToggleDisable)
		admin.Post("/admin/users/{id}/delete", s.adminDeleteUser)
		admin.Post("/admin/payments/{id}/approve", s.adminApprovePaymentVerification)
		admin.Get("/admin/registrations", s.listRegistrations)
		admin.Post("/admin/registrations/{id}/approve", s.approveRegistration)
		admin.Post("/admin/registrations/{id}/reject", s.rejectRegistration)
		admin.Get("/admin/invites", s.adminInviteGenerator)
		admin.Post("/admin/invites", s.adminGenerateInviteJWT)
	})

	return r
}

func (s *Server) handlePage(slug string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.renderMarkdownPage(w, r, slug)
	}
}

func (s *Server) pageHandler(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	slug = strings.TrimSuffix(slug, ".md")
	s.renderMarkdownPage(w, r, slug)
}

func (s *Server) renderMarkdownPage(w http.ResponseWriter, r *http.Request, slug string) {
	path := filepath.Join("pages", slug+".md")
	data, err := fs.ReadFile(s.contentFS, path)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, fmt.Sprintf("page %s not found", slug))
		return
	}
	html, err := s.renderer.Render(data)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "failed to render page")
		return
	}

	s.renderTemplate(w, r, "page.html", map[string]any{
		"Title":   humanizeSlug(slug),
		"Content": html,
		"User":    s.currentUser(r.Context()),
	})
}

func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	payload := map[string]any{
		"Year": time.Now().Year(),
	}

	switch v := data.(type) {
	case map[string]any:
		for key, value := range v {
			payload[key] = value
		}
	case nil:
		// nothing to merge
	default:
		payload["Data"] = v
	}

	if _, ok := payload["User"]; !ok {
		payload["User"] = s.currentUser(r.Context())
	}

	if err := s.templates.Execute(name, payload, w); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "render error")
	}
}

func (s *Server) renderError(w http.ResponseWriter, _ *http.Request, status int, message string) {
	w.WriteHeader(status)
	_ = s.templates.Execute("error.html", map[string]any{
		"Status":  status,
		"Message": message,
		"Year":    time.Now().Year(),
	}, w)
}

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token != "" {
		s.completeTokenLogin(w, r, token)
		return
	}
	s.clearPendingLogin(r.Context())
	s.renderLogin(w, r, map[string]any{})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, map[string]any{
			"Error": "We could not understand that request. Please try again.",
		})
		return
	}

	switch r.PostFormValue("mode") {
	case "admin":
		s.handleAdminLogin(w, r)
	case "link":
		s.handleLoginLinkRequest(w, r)
	case "otp":
		s.handleOTPVerification(w, r)
	default:
		s.renderLogin(w, r, map[string]any{
			"Error": "Unsupported login request.",
		})
	}
}

func (s *Server) getLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	s.renderDashboard(w, r, nil)
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.DuesCurrent {
		s.renderDashboard(w, r, map[string]any{
			"Error": "You must be current on dues before updating your profile.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to read your submission. Please try again.",
		})
		return
	}

	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	bio := strings.TrimSpace(r.PostFormValue("bio"))
	ssh := strings.TrimSpace(r.PostFormValue("ssh_pubkey"))
	intro := strings.TrimSpace(r.PostFormValue("introduction"))

	if displayName == "" {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Display name is required.",
		})
		return
	}
	if len(displayName) > 64 {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Display name must be 64 characters or fewer.",
		})
		return
	}
	if len(bio) > 1024 {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Bio is too long.",
		})
		return
	}
	if len(ssh) > 4096 {
		s.renderDashboard(w, r, map[string]any{
			"Error": "SSH public key is unexpectedly long.",
		})
		return
	}
	if len(intro) > 1200 {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Introduction must be 1200 characters or fewer.",
		})
		return
	}

	_, err := s.db.ExecContext(r.Context(), `UPDATE users SET display_name = ?, bio = ?, ssh_pubkey = ?, introduction = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, displayName, bio, ssh, intro, user.ID)
	if err != nil {
		log.Printf("update profile: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "We could not save your profile changes.",
		})
		return
	}
	s.sessions.Put(r.Context(), "display_name", displayName)
	s.renderDashboard(w, r, map[string]any{
		"Message": "Profile updated.",
	})
}

func (s *Server) requestEmailChange(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to read your submission. Please try again.",
		})
		return
	}

	newEmail := strings.TrimSpace(r.PostFormValue("new_email"))
	if newEmail == "" {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Enter the new email address you would like to use.",
		})
		return
	}
	if len(newEmail) > 320 {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Email addresses must be 320 characters or fewer.",
		})
		return
	}

	parsed, err := mail.ParseAddress(newEmail)
	if err != nil {
		s.renderDashboard(w, r, map[string]any{
			"Error": "That does not look like a valid email address.",
		})
		return
	}
	newEmail = strings.TrimSpace(parsed.Address)
	if newEmail == "" || !strings.Contains(newEmail, "@") {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Provide a fully-qualified email address.",
		})
		return
	}
	if strings.EqualFold(newEmail, user.Email) {
		s.renderDashboard(w, r, map[string]any{
			"Message": "That address is already on file.",
		})
		return
	}

	var existingID int
	err = s.db.QueryRowContext(r.Context(), `SELECT id FROM users WHERE LOWER(email) = LOWER(?)`, newEmail).Scan(&existingID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("check email availability: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "We could not start that email change request.",
		})
		return
	}
	if existingID != 0 && existingID != user.ID {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Another member is already using that email address.",
		})
		return
	}

	token, err := randomURLToken(32)
	if err != nil {
		log.Printf("generate email token: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to queue that change at the moment.",
		})
		return
	}
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().Add(48 * time.Hour)

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("begin email change tx: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to queue that change at the moment.",
		})
		return
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(r.Context(), `DELETE FROM email_change_requests WHERE user_id = ? AND approved_at IS NULL`, user.ID); err != nil {
		log.Printf("clear old email change: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to queue that change at the moment.",
		})
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO email_change_requests (user_id, new_email, token_hash, expires_at) VALUES (?, ?, ?, ?)`, user.ID, newEmail, hex.EncodeToString(hash[:]), expires); err != nil {
		log.Printf("insert email change: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to queue that change at the moment.",
		})
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("commit email change: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to queue that change at the moment.",
		})
		return
	}

	approvalURL := s.emailApprovalURL(r, token)
	subject := "Confirm your new dystopian.earth email"
	body := fmt.Sprintf("Hi %s,\n\nWe received a request to change your member email from %s to %s. Use the link below to approve the update.\n\n%s\n\nIf you did not make this request, ignore this message and your email will stay the same.\n", user.Name, user.Email, newEmail, approvalURL)
	if s.mailer != nil && s.mailer.Enabled() {
		s.mailer.Send(email.Message{To: []string{user.Email}, Subject: subject, Body: body})
	} else {
		log.Printf("email change approval for %s -> %s: %s", user.Email, newEmail, approvalURL)
	}

	s.renderDashboard(w, r, map[string]any{
		"Message": "Check your current inbox for a confirmation link.",
	})
}

func (s *Server) updatePayment(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to read your submission.",
		})
		return
	}

	provider := strings.TrimSpace(r.PostFormValue("payment_provider"))
	reference := strings.TrimSpace(r.PostFormValue("payment_ref"))
	if len(provider) > 120 {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Provider description is too long.",
		})
		return
	}
	if len(reference) > 200 {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Reference is too long.",
		})
		return
	}

	normalized, ok := supportedPaymentProviders[strings.ToLower(provider)]
	if !ok {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Choose a supported payment provider (Stripe, Venmo, PayPal, or Bitcoin).",
		})
		return
	}

	_, err := s.db.ExecContext(r.Context(), `UPDATE users SET payment_provider = ?, payment_ref = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, normalized, reference, user.ID)
	if err != nil {
		log.Printf("update payment: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "We were unable to save payment details.",
		})
		return
	}

	if err := s.enqueuePaymentVerification(r.Context(), user.ID, normalized, reference); err != nil {
		log.Printf("queue payment verification: %v", err)
	}

	s.renderDashboard(w, r, map[string]any{
		"Message": "Payment update submitted for verification.",
	})
}

func (s *Server) enqueuePaymentVerification(ctx context.Context, userID int, provider, reference string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO payment_verifications (user_id, provider, reference) VALUES (?, ?, ?)`, userID, provider, reference)
	return err
}

func (s *Server) updateOTP(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.DuesCurrent {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Bring your dues current to manage one-time passwords.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to read your submission.",
		})
		return
	}

	action := strings.TrimSpace(r.PostFormValue("action"))
	switch action {
	case "enable":
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "dystopian.earth", AccountName: user.Email})
		if err != nil {
			log.Printf("generate otp secret: %v", err)
			s.renderDashboard(w, r, map[string]any{
				"Error": "Unable to generate an OTP secret.",
			})
			return
		}
		secret := key.Secret()
		_, err = s.db.ExecContext(r.Context(), `UPDATE users SET otp_secret = ?, otp_enabled_at = CURRENT_TIMESTAMP WHERE id = ?`, secret, user.ID)
		if err != nil {
			log.Printf("store otp secret: %v", err)
			s.renderDashboard(w, r, map[string]any{
				"Error": "Failed to store the OTP secret.",
			})
			return
		}
		s.renderDashboard(w, r, map[string]any{
			"Message":   "Authenticator secret generated. Configure your app right away.",
			"OTPSecret": secret,
			"OTPURI":    key.URL(),
		})
	case "disable":
		_, err := s.db.ExecContext(r.Context(), `UPDATE users SET otp_secret = '', otp_enabled_at = NULL WHERE id = ?`, user.ID)
		if err != nil {
			log.Printf("disable otp: %v", err)
			s.renderDashboard(w, r, map[string]any{
				"Error": "We could not disable OTP for this account.",
			})
			return
		}
		s.renderDashboard(w, r, map[string]any{
			"Message": "One-time passwords disabled.",
		})
	default:
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unsupported OTP action.",
		})
	}
}

func (s *Server) updateLDAP(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.DuesCurrent {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Bring your dues current to manage LDAP credentials.",
		})
		return
	}
	if s.cipher == nil {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Server is not configured with an encryption key for LDAP passwords.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to read your submission.",
		})
		return
	}

	action := strings.TrimSpace(r.PostFormValue("action"))
	switch action {
	case "clear":
		_, err := s.db.ExecContext(r.Context(), `UPDATE users SET ldap_password_encrypted = '' WHERE id = ?`, user.ID)
		if err != nil {
			log.Printf("clear ldap password: %v", err)
			s.renderDashboard(w, r, map[string]any{
				"Error": "Unable to clear the LDAP password.",
			})
			return
		}
		s.renderDashboard(w, r, map[string]any{
			"Message": "LDAP password cleared.",
		})
	case "set":
		password := r.PostFormValue("ldap_password")
		if strings.TrimSpace(password) == "" {
			s.renderDashboard(w, r, map[string]any{
				"Error": "Provide a password to store.",
			})
			return
		}
		if len(password) < 8 {
			s.renderDashboard(w, r, map[string]any{
				"Error": "Passwords must be at least 8 characters.",
			})
			return
		}
		encrypted, err := s.cipher.Encrypt([]byte(password))
		if err != nil {
			log.Printf("encrypt ldap password: %v", err)
			s.renderDashboard(w, r, map[string]any{
				"Error": "Unable to encrypt the password.",
			})
			return
		}
		_, err = s.db.ExecContext(r.Context(), `UPDATE users SET ldap_password_encrypted = ? WHERE id = ?`, encrypted, user.ID)
		if err != nil {
			log.Printf("store ldap password: %v", err)
			s.renderDashboard(w, r, map[string]any{
				"Error": "Unable to store the LDAP password.",
			})
			return
		}
		s.renderDashboard(w, r, map[string]any{
			"Message": "LDAP password saved securely.",
		})
	default:
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unsupported LDAP action.",
		})
	}
}

func (s *Server) generateWireguard(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.DuesCurrent {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Bring your dues current to generate VPN credentials.",
		})
		return
	}
	if s.cipher == nil {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Server is not configured with an encryption key for VPN credentials.",
		})
		return
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Printf("wireguard private key: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to generate a WireGuard keypair.",
		})
		return
	}
	preshared, err := wgtypes.GenerateKey()
	if err != nil {
		log.Printf("wireguard preshared: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to generate a WireGuard pre-shared key.",
		})
		return
	}
	password, err := randomPassword()
	if err != nil {
		log.Printf("wireguard password: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to mint a password for your WireGuard config.",
		})
		return
	}

	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.66.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <portal-public-key>
PresharedKey = %s
Endpoint = vpn.dystopian.earth:51820
AllowedIPs = 0.0.0.0/0, ::/0
`, privateKey.String(), preshared.String())

	encryptedConfig, err := s.cipher.Encrypt([]byte(config))
	if err != nil {
		log.Printf("encrypt wireguard config: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to encrypt the WireGuard configuration.",
		})
		return
	}
	encryptedPassword, err := s.cipher.Encrypt([]byte(password))
	if err != nil {
		log.Printf("encrypt wireguard password: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to store the WireGuard password.",
		})
		return
	}

	_, err = s.db.ExecContext(r.Context(), `UPDATE users SET wireguard_config_encrypted = ?, wireguard_password_encrypted = ? WHERE id = ?`, encryptedConfig, encryptedPassword, user.ID)
	if err != nil {
		log.Printf("store wireguard config: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to store the WireGuard configuration.",
		})
		return
	}

	s.renderDashboard(w, r, map[string]any{
		"Message":           "WireGuard credentials generated. Save this password in a secure place.",
		"WireguardConfig":   config,
		"WireguardPassword": password,
	})
}

func (s *Server) createMemberInvite(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !user.DuesCurrent {
		s.renderDashboard(w, r, map[string]any{
			"Error": "Bring your dues current before generating invite codes.",
		})
		return
	}
	if s.cfg.MaxInvites > 0 {
		count, err := s.countMemberInvites(r.Context(), user.ID)
		if err != nil {
			log.Printf("count invites: %v", err)
			s.renderDashboard(w, r, map[string]any{
				"Error": "Unable to check invite limits at this time.",
			})
			return
		}
		if count >= s.cfg.MaxInvites {
			s.renderDashboard(w, r, map[string]any{
				"Error": "You have reached the invite limit. Contact an admin for more.",
			})
			return
		}
	}

	var code string
	var err error
	for attempts := 0; attempts < 3; attempts++ {
		code, err = generateInviteCode()
		if err != nil {
			break
		}
		_, err = s.db.ExecContext(r.Context(), `INSERT INTO invite_codes (code, created_by) VALUES (?, ?)`, code, user.ID)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Printf("create invite code: %v", err)
		s.renderDashboard(w, r, map[string]any{
			"Error": "Unable to generate an invite code right now.",
		})
		return
	}

	s.renderDashboard(w, r, map[string]any{
		"Message":   "Invite code minted successfully.",
		"NewInvite": code,
	})
}

func (s *Server) listRegistrations(w http.ResponseWriter, r *http.Request) {
	regs, err := s.pendingRegistrations(r.Context())
	if err != nil {
		log.Printf("list registrations: %v", err)
		s.renderError(w, r, http.StatusInternalServerError, "Unable to load registrations")
		return
	}
	data := map[string]any{
		"Registrations": regs,
	}
	switch r.URL.Query().Get("status") {
	case "approved":
		data["Message"] = "Registration approved and welcome email sent."
	case "rejected":
		data["Message"] = "Registration rejected."
	case "error":
		data["Error"] = "Unable to update that registration."
	}
	s.renderTemplate(w, r, "admin_registrations.html", data)
}

func (s *Server) approveRegistration(w http.ResponseWriter, r *http.Request) {
	adminID := s.sessions.GetInt(r.Context(), "user_id")
	if adminID == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid registration id", http.StatusBadRequest)
		return
	}

	token, email, name, err := s.finalizeRegistration(r.Context(), id, adminID)
	if err != nil {
		log.Printf("approve registration %d: %v", id, err)
		http.Redirect(w, r, "/admin/registrations?status=error", http.StatusSeeOther)
		return
	}
	if token != "" {
		s.sendWelcomeEmail(r, email, name, token)
	}
	http.Redirect(w, r, "/admin/registrations?status=approved", http.StatusSeeOther)
}

func (s *Server) rejectRegistration(w http.ResponseWriter, r *http.Request) {
	adminID := s.sessions.GetInt(r.Context(), "user_id")
	if adminID == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/registrations?status=error", http.StatusSeeOther)
		return
	}
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/admin/registrations?status=error", http.StatusSeeOther)
		return
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	if len(note) > 1000 {
		note = note[:1000]
	}
	if err := s.setRegistrationStatus(r.Context(), id, adminID, "rejected", note); err != nil {
		log.Printf("reject registration %d: %v", id, err)
		http.Redirect(w, r, "/admin/registrations?status=error", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/registrations?status=rejected", http.StatusSeeOther)
}

func (s *Server) adminInviteGenerator(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
		data["InviteToken"] = token
	}
	if claims := strings.TrimSpace(r.URL.Query().Get("claims")); claims != "" {
		data["ClaimsInput"] = claims
	}
	switch r.URL.Query().Get("status") {
	case "error":
		data["Error"] = "Unable to generate that token."
	case "sent":
		data["Message"] = "Invite token generated."
	}
	s.renderTemplate(w, r, "admin_invites.html", data)
}

func (s *Server) adminGenerateInviteJWT(w http.ResponseWriter, r *http.Request) {
	if s.inviteJWT == nil {
		s.renderTemplate(w, r, "admin_invites.html", map[string]any{
			"Error": "Invite token service is not available.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderTemplate(w, r, "admin_invites.html", map[string]any{
			"Error": "Unable to read that submission.",
		})
		return
	}
	claimsRaw := strings.TrimSpace(r.PostFormValue("claims"))
	if claimsRaw == "" {
		s.renderTemplate(w, r, "admin_invites.html", map[string]any{
			"Error":       "Provide JSON claims to sign.",
			"ClaimsInput": "{}",
		})
		return
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(claimsRaw), &payload); err != nil {
		s.renderTemplate(w, r, "admin_invites.html", map[string]any{
			"Error":       "Claims must be valid JSON.",
			"ClaimsInput": claimsRaw,
		})
		return
	}
	if payload == nil {
		payload = map[string]any{}
	}
	if _, ok := payload["aud"]; !ok {
		payload["aud"] = "dystopian.earth"
	}

	claims := jwt.MapClaims{}
	for key, value := range payload {
		claims[key] = value
	}

	token, err := s.inviteJWT.SignClaims(claims)
	if err != nil {
		log.Printf("sign invite claims: %v", err)
		s.renderTemplate(w, r, "admin_invites.html", map[string]any{
			"Error":       "Unable to sign those claims right now.",
			"ClaimsInput": claimsRaw,
		})
		return
	}

	pretty, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		pretty = []byte(claimsRaw)
	}

	s.renderTemplate(w, r, "admin_invites.html", map[string]any{
		"Message":      "Invite token generated.",
		"InviteToken":  token,
		"ClaimsInput":  claimsRaw,
		"ClaimsOutput": string(pretty),
	})
}

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	users, err := s.allUsers(r.Context())
	if err != nil {
		log.Printf("list users: %v", err)
		s.renderError(w, r, http.StatusInternalServerError, "Unable to load admin dashboard")
		return
	}

	queue, err := s.pendingPaymentVerifications(r.Context())
	if err != nil {
		log.Printf("list payment verifications: %v", err)
	}

	data := map[string]any{
		"Users":                users,
		"MailerConfigured":     s.mailer != nil && s.mailer.Enabled(),
		"EnvironmentVariables": s.environmentInsights(),
		"RuntimeSettings":      s.runtimeSettings(),
	}
	if err == nil {
		data["PaymentQueue"] = queue
	}

	switch r.URL.Query().Get("status") {
	case "email-sent":
		data["Message"] = "Test email dispatched. Check the recipient inbox."
	case "deleted":
		data["Message"] = "User account removed."
	case "error":
		data["Error"] = "Unable to complete that request."
	case "mailer-disabled":
		data["Error"] = "Email service is not configured."
	case "missing-recipient":
		data["Error"] = "Provide a valid recipient for test emails."
	case "invalid-recipient":
		data["Error"] = "That email address is not valid."
	case "payment-approved":
		data["Message"] = "Payment update marked as verified."
	}

	s.renderTemplate(w, r, "admin_dashboard.html", data)
}

type envVarInsight struct {
	Name      string
	RawValue  string
	Effective string
	Source    string
}

func (s *Server) environmentInsights() []envVarInsight {
	var insights []envVarInsight

	add := func(name string, effective string) {
		raw := "(default)"
		source := "default"
		if val, ok := os.LookupEnv(name); ok {
			raw = val
			source = "environment"
		}
		insights = append(insights, envVarInsight{
			Name:      name,
			RawValue:  raw,
			Effective: effective,
			Source:    source,
		})
	}

	add("PORTAL_ADDR", s.cfg.Addr)
	add("PORTAL_DSN", s.cfg.DSN)
	add("PORTAL_REDIS_ADDR", s.cfg.RedisAddr)
	add("PORTAL_REDIS_PASSWORD", s.cfg.RedisPassword)
	add("PORTAL_SESSION_TTL", s.cfg.SessionTTL.String())
	add("PORTAL_INVITE_SECRET", s.cfg.InviteSecret)
	add("PORTAL_FLAG_SECRET", s.cfg.FlagSecret)
	add("PORTAL_CONTENT_DIR", s.cfg.ContentDir)
	add("PORTAL_TEMPLATES_DIR", s.cfg.TemplatesDir)
	add("PORTAL_STATIC_DIR", s.cfg.StaticDir)
	add("PORTAL_SMTP_HOST", s.cfg.SMTPHost)
	add("PORTAL_SMTP_PORT", strconv.Itoa(s.cfg.SMTPPort))
	add("PORTAL_SMTP_USERNAME", s.cfg.SMTPUsername)
	add("PORTAL_SMTP_TOKEN", s.cfg.SMTPToken)
	add("PORTAL_SMTP_TLS", strconv.FormatBool(s.cfg.SMTPUseTLS))
	add("PORTAL_EMAIL_FROM", s.cfg.EmailFrom)
	add("PORTAL_ADMIN_EMAIL", s.cfg.AdminEmail)
	add("PORTAL_TOR_SOCKS", s.cfg.TorSOCKS)
	add("PORTAL_TOR_CONTROL", s.cfg.TorControl)
	add("PORTAL_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(s.cfg.EncryptionKey))
	add("PORTAL_MEMBER_INVITES", strconv.Itoa(s.cfg.MaxInvites))

	return insights
}

type runtimeConfigInsight struct {
	Name  string
	Value string
}

func (s *Server) runtimeSettings() []runtimeConfigInsight {
	var insights []runtimeConfigInsight

	add := func(name string, value any) {
		insights = append(insights, runtimeConfigInsight{
			Name:  name,
			Value: fmt.Sprint(value),
		})
	}

	if s.sessions != nil {
		add("Session Lifetime", s.sessions.Lifetime)
		add("Session Idle Timeout", s.sessions.IdleTimeout)
		add("Session Cookie Name", s.sessions.Cookie.Name)
		add("Session Cookie Domain", s.sessions.Cookie.Domain)
		add("Session Cookie Path", s.sessions.Cookie.Path)
		add("Session Cookie Secure", s.sessions.Cookie.Secure)
		add("Session Cookie HTTPOnly", s.sessions.Cookie.HttpOnly)
		add("Session Cookie Persist", s.sessions.Cookie.Persist)
		add("Session Cookie SameSite", sameSiteMode(s.sessions.Cookie.SameSite))
	}

	if s.inviteJWT != nil {
		add("Invite Token Lifetime", s.inviteJWT.Lifetime())
	}

	add("Mailer Enabled", s.mailer != nil && s.mailer.Enabled())

	if s.redisPool != nil {
		add("Redis Max Idle", s.redisPool.MaxIdle)
		add("Redis Max Active", s.redisPool.MaxActive)
		add("Redis Idle Timeout", s.redisPool.IdleTimeout)
	}

	add("Cipher Configured", s.cipher != nil)
	add("Content Directory", s.cfg.ContentDir)
	add("Templates Directory", s.cfg.TemplatesDir)
	add("Static Directory", s.cfg.StaticDir)
	add("Tor SOCKS Proxy", s.cfg.TorSOCKS)
	add("Tor Control Address", s.cfg.TorControl)

	return insights
}

func sameSiteMode(mode http.SameSite) string {
	switch mode {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return fmt.Sprintf("Unknown(%d)", mode)
	}
}

func (s *Server) adminSendTestEmail(w http.ResponseWriter, r *http.Request) {
	if s.mailer == nil || !s.mailer.Enabled() {
		http.Redirect(w, r, "/admin?status=mailer-disabled", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	recipient := strings.TrimSpace(r.PostFormValue("to"))
	if recipient == "" {
		recipient = s.sessions.GetString(r.Context(), "email")
	}
	if recipient == "" {
		http.Redirect(w, r, "/admin?status=missing-recipient", http.StatusSeeOther)
		return
	}
	if _, err := mail.ParseAddress(recipient); err != nil {
		http.Redirect(w, r, "/admin?status=invalid-recipient", http.StatusSeeOther)
		return
	}
	subject := strings.TrimSpace(r.PostFormValue("subject"))
	if subject == "" {
		subject = "dystopian.earth mailer test"
	}
	body := strings.TrimSpace(r.PostFormValue("body"))
	if body == "" {
		body = "This is a test email from the dystopian.earth admin console."
	}

	s.mailer.Send(email.Message{To: []string{recipient}, Subject: subject, Body: body})
	http.Redirect(w, r, "/admin?status=email-sent", http.StatusSeeOther)
}

func (s *Server) adminApprovePaymentVerification(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id <= 0 {
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	adminID := s.sessions.GetInt(r.Context(), "user_id")
	if adminID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	res, err := s.db.ExecContext(r.Context(), `UPDATE payment_verifications SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ? AND status = 'pending'`, adminID, id)
	if err != nil {
		log.Printf("approve payment verification %d: %v", id, err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	affected, err := res.RowsAffected()
	if err != nil {
		log.Printf("payment verification rows: %v", err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	if affected == 0 {
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin?status=payment-approved", http.StatusSeeOther)
}

func (s *Server) adminViewUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	profile, err := s.loadAdminUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderError(w, r, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("load admin user %d: %v", id, err)
		s.renderError(w, r, http.StatusInternalServerError, "Unable to load that user")
		return
	}

	data := map[string]any{"Profile": profile, "PaymentProviders": paymentProviderOptions}
	switch r.URL.Query().Get("status") {
	case "updated":
		data["Message"] = "User profile updated."
	case "promoted":
		data["Message"] = "User promoted to administrator."
	case "disabled":
		data["Message"] = "User access disabled."
	case "enabled":
		data["Message"] = "User access restored."
	case "cannot-self-demote":
		data["Error"] = "You cannot remove your own administrator access."
	case "last-admin":
		data["Error"] = "At least one enabled administrator must remain."
	case "invalid":
		data["Error"] = "Unable to apply those changes."
	}
	s.renderTemplate(w, r, "admin_user.html", data)
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	profile, err := s.loadAdminUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderError(w, r, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("load admin user %d: %v", id, err)
		s.renderError(w, r, http.StatusInternalServerError, "Unable to load that user")
		return
	}
	originalEmail := profile.Email
	if err := r.ParseForm(); err != nil {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Unable to read that submission.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}

	emailValue := strings.TrimSpace(r.PostFormValue("email"))
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	bio := strings.TrimSpace(r.PostFormValue("bio"))
	paymentProvider := strings.TrimSpace(r.PostFormValue("payment_provider"))
	paymentRef := strings.TrimSpace(r.PostFormValue("payment_ref"))
	duesCurrent := r.PostFormValue("dues_current") == "on"
	makeAdmin := r.PostFormValue("is_admin") == "on"

	profile.Email = emailValue
	profile.DisplayName = displayName
	profile.Bio = bio
	profile.PaymentProvider = paymentProvider
	profile.PaymentRef = paymentRef
	profile.DuesCurrent = duesCurrent || makeAdmin
	profile.Admin = makeAdmin

	if emailValue == "" {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Email is required.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}
	parsedEmail, err := mail.ParseAddress(emailValue)
	if err != nil {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Provide a valid email address.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}
	emailValue = strings.TrimSpace(parsedEmail.Address)
	if emailValue == "" || !strings.Contains(emailValue, "@") {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Provide a fully-qualified email address.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}

	var existingID int
	err = s.db.QueryRowContext(r.Context(), `SELECT id FROM users WHERE LOWER(email) = LOWER(?)`, emailValue).Scan(&existingID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("admin email availability: %v", err)
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Unable to validate that email right now.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}
	if existingID != 0 && existingID != id {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Another member already uses that email.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}

	if displayName == "" {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Display name is required.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}
	if len(displayName) > 64 {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Display name must be 64 characters or fewer.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}
	if len(bio) > 1024 {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Bio is too long.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}
	if len(paymentProvider) > 128 || len(paymentRef) > 128 {
		s.renderTemplate(w, r, "admin_user.html", map[string]any{
			"Error":            "Payment details are too long.",
			"Profile":          profile,
			"PaymentProviders": paymentProviderOptions,
		})
		return
	}

	if paymentProvider != "" {
		if normalized, ok := supportedPaymentProviders[strings.ToLower(paymentProvider)]; ok {
			paymentProvider = normalized
		} else {
			s.renderTemplate(w, r, "admin_user.html", map[string]any{
				"Error":            "Payment provider must be Stripe, Venmo, PayPal, or Bitcoin.",
				"Profile":          profile,
				"PaymentProviders": paymentProviderOptions,
			})
			return
		}
	}
	profile.PaymentProvider = paymentProvider

	if makeAdmin {
		duesCurrent = true
	}

	if profile.Admin && !makeAdmin {
		currentID := s.sessions.GetInt(r.Context(), "user_id")
		if currentID == id {
			http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=cannot-self-demote", id), http.StatusSeeOther)
			return
		}
		ok, err := s.hasOtherAdmins(r.Context(), id)
		if err != nil {
			log.Printf("check admins: %v", err)
			http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
			return
		}
		if !ok {
			http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=last-admin", id), http.StatusSeeOther)
			return
		}
	}

	emailChanged := !strings.EqualFold(originalEmail, emailValue)

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("begin admin update user %d: %v", id, err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
		return
	}
	defer tx.Rollback()

	if emailChanged {
		if _, err := tx.ExecContext(r.Context(), `UPDATE users SET fallback_email = email WHERE id = ?`, id); err != nil {
			log.Printf("store fallback email %d: %v", id, err)
			http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
			return
		}
	}

	_, err = tx.ExecContext(r.Context(), `UPDATE users SET email = ?, display_name = ?, bio = ?, payment_provider = ?, payment_ref = ?, dues_current = ?, is_admin = ? WHERE id = ?`, emailValue, displayName, bio, paymentProvider, paymentRef, boolToInt(duesCurrent), boolToInt(makeAdmin), id)
	if err != nil {
		log.Printf("update user %d: %v", id, err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("commit admin update %d: %v", id, err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
		return
	}

	profile.Email = emailValue
	if emailChanged {
		profile.FallbackEmail = originalEmail
	}

	if emailChanged && s.mailer != nil && s.mailer.Enabled() {
		subject := "Member email updated by an administrator"
		body := fmt.Sprintf("Hello,\n\nYour dystopian.earth account email was updated to %s by an administrator. The previous address %s remains on file as a fallback.\n", emailValue, originalEmail)
		s.mailer.Send(email.Message{To: []string{emailValue}, Subject: subject, Body: body})
		if originalEmail != "" {
			s.mailer.Send(email.Message{To: []string{originalEmail}, Subject: subject, Body: body})
		}
	}

	http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=updated", id), http.StatusSeeOther)
}

func (s *Server) adminPromoteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	_, err = s.db.ExecContext(r.Context(), `UPDATE users SET is_admin = 1, dues_current = 1 WHERE id = ?`, id)
	if err != nil {
		log.Printf("promote user %d: %v", id, err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=promoted", id), http.StatusSeeOther)
}

func (s *Server) adminToggleDisable(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	var (
		adminFlag int
		disabled  int
	)
	err = s.db.QueryRowContext(r.Context(), `SELECT is_admin, is_disabled FROM users WHERE id = ?`, id).Scan(&adminFlag, &disabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderError(w, r, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("load user %d for disable: %v", id, err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
		return
	}
	currentID := s.sessions.GetInt(r.Context(), "user_id")
	if currentID == id {
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
		return
	}
	newValue := 1
	status := "disabled"
	if disabled == 1 {
		newValue = 0
		status = "enabled"
	}
	if adminFlag == 1 && newValue == 1 {
		ok, err := s.hasOtherAdmins(r.Context(), id)
		if err != nil {
			log.Printf("check admins: %v", err)
			http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
			return
		}
		if !ok {
			http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=last-admin", id), http.StatusSeeOther)
			return
		}
	}

	_, err = s.db.ExecContext(r.Context(), `UPDATE users SET is_disabled = ? WHERE id = ?`, newValue, id)
	if err != nil {
		log.Printf("toggle disable %d: %v", id, err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=invalid", id), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=%s", id, status), http.StatusSeeOther)
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	currentID := s.sessions.GetInt(r.Context(), "user_id")
	if currentID == id {
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}

	var adminFlag int
	err = s.db.QueryRowContext(r.Context(), `SELECT is_admin FROM users WHERE id = ?`, id).Scan(&adminFlag)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.renderError(w, r, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("load user %d: %v", id, err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	if adminFlag == 1 {
		ok, err := s.hasOtherAdmins(r.Context(), id)
		if err != nil {
			log.Printf("check admins: %v", err)
			http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
			return
		}
		if !ok {
			http.Redirect(w, r, fmt.Sprintf("/admin/users/%d?status=last-admin", id), http.StatusSeeOther)
			return
		}
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("begin delete user %d: %v", id, err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(r.Context(), `DELETE FROM login_tokens WHERE user_id = ?`, id); err != nil {
		log.Printf("delete login tokens %d: %v", id, err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE invite_codes SET used_by = NULL WHERE used_by = ?`, id); err != nil {
		log.Printf("clear invite usage %d: %v", id, err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE invite_codes SET created_by = NULL WHERE created_by = ?`, id); err != nil {
		log.Printf("clear invite ownership %d: %v", id, err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM users WHERE id = ?`, id); err != nil {
		log.Printf("delete user %d: %v", id, err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("commit delete user %d: %v", id, err)
		http.Redirect(w, r, "/admin?status=error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin?status=deleted", http.StatusSeeOther)
}

type registrationEntry struct {
	ID              int
	Email           string
	DisplayName     string
	InviteCode      string
	InviteSummary   string
	InviteClaims    []claimPair
	InviteFallback  string
	ChallengeAnswer string
	SSHPubKey       string
	Introduction    string
	CreatedAt       time.Time
}

type claimPair struct {
	Key   string
	Value string
}

type adminUserRow struct {
	ID          int
	Email       string
	DisplayName string
	Admin       bool
	DuesCurrent bool
	Disabled    bool
	CreatedAt   time.Time
	ApprovedAt  *time.Time
}

type adminUserProfile struct {
	adminUserRow
	Bio                 string
	PaymentProvider     string
	PaymentRef          string
	Introduction        string
	SSHPubKey           string
	OTPEnabledAt        *time.Time
	OTPConfigured       bool
	LDAPConfigured      bool
	WireguardConfigured bool
	FallbackEmail       string
}

func (s *Server) pendingRegistrations(ctx context.Context) ([]registrationEntry, error) {
	const query = `SELECT id, email, display_name, invite_code, challenge_answer, ssh_pubkey, introduction, created_at FROM registrations WHERE status = 'pending' ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var regs []registrationEntry
	for rows.Next() {
		var (
			entry           registrationEntry
			challengeAnswer sql.NullString
			sshPubKey       sql.NullString
			introduction    sql.NullString
		)
		if err := rows.Scan(&entry.ID, &entry.Email, &entry.DisplayName, &entry.InviteCode, &challengeAnswer, &sshPubKey, &introduction, &entry.CreatedAt); err != nil {
			return nil, err
		}
		if challengeAnswer.Valid {
			entry.ChallengeAnswer = challengeAnswer.String
		}
		if sshPubKey.Valid {
			entry.SSHPubKey = sshPubKey.String
		}
		if introduction.Valid {
			entry.Introduction = introduction.String
		}
		summary, claims, fallback := summarizeInviteToken(entry.InviteCode)
		entry.InviteSummary = summary
		entry.InviteClaims = claims
		entry.InviteFallback = fallback
		regs = append(regs, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return regs, nil
}

func (s *Server) pendingPaymentVerifications(ctx context.Context) ([]paymentVerificationEntry, error) {
	const query = `SELECT pv.id, pv.user_id, u.display_name, u.email, pv.provider, pv.reference, pv.created_at FROM payment_verifications pv JOIN users u ON u.id = pv.user_id WHERE pv.status = 'pending' ORDER BY pv.created_at`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []paymentVerificationEntry
	for rows.Next() {
		var entry paymentVerificationEntry
		if err := rows.Scan(&entry.ID, &entry.UserID, &entry.Name, &entry.Email, &entry.Provider, &entry.Reference, &entry.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func summarizeInviteToken(token string) (string, []claimPair, string) {
	if token == "" {
		return "", nil, ""
	}

	fallback := truncateInviteCode(token)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return fallback, nil, fallback
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return fallback, nil, fallback
	}

	interesting := []string{"handle", "email", "aud", "exp", "iat", "iss", "sub"}
	pairs := make([]claimPair, 0, len(interesting))
	summaryParts := make([]string, 0, 3)
	for _, key := range interesting {
		value, exists := claims[key]
		if !exists {
			continue
		}
		formatted := formatInviteClaim(key, value)
		if formatted == "" {
			continue
		}
		pairs = append(pairs, claimPair{Key: key, Value: formatted})
		switch key {
		case "handle", "email":
			summaryParts = append(summaryParts, formatted)
		case "exp":
			summaryParts = append(summaryParts, "exp "+formatted)
		}
	}

	if len(pairs) == 0 {
		return fallback, nil, fallback
	}

	summary := strings.Join(summaryParts, " · ")
	if summary == "" {
		summary = "Invite token"
	}
	return summary, pairs, fallback
}

func (s *Server) allUsers(ctx context.Context) ([]adminUserRow, error) {
	const query = `SELECT id, email, display_name, is_admin, dues_current, is_disabled, created_at, approved_at FROM users ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []adminUserRow
	for rows.Next() {
		var (
			row      adminUserRow
			admin    int
			dues     int
			disabled int
			approved sql.NullTime
		)
		if err := rows.Scan(&row.ID, &row.Email, &row.DisplayName, &admin, &dues, &disabled, &row.CreatedAt, &approved); err != nil {
			return nil, err
		}
		row.Admin = admin == 1
		row.DuesCurrent = row.Admin || dues == 1
		row.Disabled = disabled == 1
		if approved.Valid {
			t := approved.Time
			row.ApprovedAt = &t
		}
		users = append(users, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *Server) loadAdminUser(ctx context.Context, id int) (*adminUserProfile, error) {
	const query = `SELECT id, email, fallback_email, display_name, bio, payment_provider, payment_ref, dues_current, is_admin, is_disabled, created_at, approved_at, otp_secret, otp_enabled_at, ssh_pubkey, introduction, ldap_password_encrypted, wireguard_config_encrypted FROM users WHERE id = ?`

	var (
		userID       int
		email        string
		fallback     sql.NullString
		name         string
		bio          string
		provider     string
		paymentRef   string
		dues         int
		adminFlag    int
		disabledFlag int
		created      time.Time
		approved     sql.NullTime
		otpSecret    sql.NullString
		otpEnabled   sql.NullTime
		sshKey       sql.NullString
		intro        sql.NullString
		ldapSecret   sql.NullString
		wgSecret     sql.NullString
	)

	err := s.db.QueryRowContext(ctx, query, id).Scan(&userID, &email, &fallback, &name, &bio, &provider, &paymentRef, &dues, &adminFlag, &disabledFlag, &created, &approved, &otpSecret, &otpEnabled, &sshKey, &intro, &ldapSecret, &wgSecret)
	if err != nil {
		return nil, err
	}

	profile := &adminUserProfile{
		adminUserRow: adminUserRow{
			ID:          userID,
			Email:       email,
			DisplayName: name,
			Admin:       adminFlag == 1,
			DuesCurrent: dues == 1,
			Disabled:    disabledFlag == 1,
			CreatedAt:   created,
		},
		Bio:             bio,
		PaymentProvider: provider,
		PaymentRef:      paymentRef,
		FallbackEmail:   strings.TrimSpace(fallback.String),
	}
	if profile.Admin {
		profile.DuesCurrent = true
	}
	if approved.Valid {
		t := approved.Time
		profile.ApprovedAt = &t
	}
	if otpSecret.Valid && strings.TrimSpace(otpSecret.String) != "" {
		profile.OTPConfigured = true
	}
	if otpEnabled.Valid {
		t := otpEnabled.Time
		profile.OTPEnabledAt = &t
	}
	if sshKey.Valid {
		profile.SSHPubKey = sshKey.String
	}
	if intro.Valid {
		profile.Introduction = intro.String
	}
	if ldapSecret.Valid && strings.TrimSpace(ldapSecret.String) != "" {
		profile.LDAPConfigured = true
	}
	if wgSecret.Valid && strings.TrimSpace(wgSecret.String) != "" {
		profile.WireguardConfigured = true
	}
	return profile, nil
}

func (s *Server) hasOtherAdmins(ctx context.Context, excludeID int) (bool, error) {
	const query = `SELECT COUNT(1) FROM users WHERE is_admin = 1 AND is_disabled = 0 AND id != ?`
	var count int
	if err := s.db.QueryRowContext(ctx, query, excludeID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func formatInviteClaim(key string, value any) string {
	switch v := value.(type) {
	case string:
		if key == "exp" || key == "iat" {
			if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
				return time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				return t.UTC().Format(time.RFC3339)
			}
		}
		return v
	case float64:
		if key == "exp" || key == "iat" {
			return time.Unix(int64(v), 0).UTC().Format(time.RFC3339)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		if key == "exp" || key == "iat" {
			if ts, err := v.Int64(); err == nil {
				return time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		}
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	case time.Time:
		return v.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func truncateInviteCode(code string) string {
	code = strings.TrimSpace(code)
	if len(code) <= 24 {
		return code
	}
	return code[:24] + "…"
}

func (s *Server) finalizeRegistration(ctx context.Context, regID, adminID int) (string, string, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", "", err
	}
	defer tx.Rollback()

	const selectSQL = `SELECT status, email, display_name, invite_code, ssh_pubkey, introduction FROM registrations WHERE id = ?`
	var (
		status     string
		email      string
		name       string
		inviteCode string
		sshKey     sql.NullString
		intro      sql.NullString
	)
	if err := tx.QueryRowContext(ctx, selectSQL, regID).Scan(&status, &email, &name, &inviteCode, &sshKey, &intro); err != nil {
		return "", "", "", err
	}
	if status != "pending" {
		return "", "", "", fmt.Errorf("registration %d is not pending", regID)
	}

	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE email = ?`, email).Scan(&existing); err != nil {
		return "", "", "", err
	}
	if existing > 0 {
		return "", "", "", fmt.Errorf("user with email %s already exists", email)
	}

	tempPassword, err := randomPassword()
	if err != nil {
		return "", "", "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.MinCost)
	if err != nil {
		return "", "", "", err
	}

	sshValue := ""
	if sshKey.Valid {
		sshValue = sshKey.String
	}
	introValue := ""
	if intro.Valid {
		introValue = intro.String
	}

	res, err := tx.ExecContext(ctx, `INSERT INTO users (email, password_hash, display_name, bio, payment_provider, payment_ref, approved_at, ssh_pubkey, introduction, dues_current) VALUES (?, ?, ?, ?, '', '', CURRENT_TIMESTAMP, ?, ?, 0)`, email, string(hash), name, introValue, sshValue, introValue)
	if err != nil {
		return "", "", "", err
	}
	userID64, err := res.LastInsertId()
	if err != nil {
		return "", "", "", err
	}
	userID := int(userID64)

	if strings.Count(inviteCode, ".") != 2 {
		if _, err := tx.ExecContext(ctx, `UPDATE invite_codes SET used_by = ?, used_at = CURRENT_TIMESTAMP WHERE code = ? AND used_at IS NULL`, userID, inviteCode); err != nil {
			return "", "", "", err
		}
	}

	if _, err := tx.ExecContext(ctx, `UPDATE registrations SET status = 'approved', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?`, adminID, regID); err != nil {
		return "", "", "", err
	}

	if err := tx.Commit(); err != nil {
		return "", "", "", err
	}

	token, err := s.createLoginToken(ctx, userID)
	if err != nil {
		return "", "", "", err
	}
	return token, email, name, nil
}

func (s *Server) setRegistrationStatus(ctx context.Context, regID, adminID int, status, note string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE registrations SET status = ?, review_note = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'`, status, note, adminID, regID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("registration %d already processed", regID)
	}
	return nil
}

func (s *Server) adminEmails(ctx context.Context) ([]string, error) {
	const query = `SELECT email FROM users WHERE is_admin = 1`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		email = strings.TrimSpace(email)
		if email != "" {
			emails = append(emails, email)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(emails) == 0 && s.cfg.AdminEmail != "" {
		emails = append(emails, s.cfg.AdminEmail)
	}
	return emails, nil
}

func (s *Server) notifyAdminsOfRegistration(ctx context.Context, regID int64, form joinForm) {
	if s.mailer == nil || !s.mailer.Enabled() {
		log.Printf("registration %d submitted for %s <%s>", regID, form.Handle, form.Email)
		return
	}
	emails, err := s.adminEmails(ctx)
	if err != nil {
		log.Printf("admin emails: %v", err)
		return
	}
	if len(emails) == 0 {
		return
	}
	subject := fmt.Sprintf("New membership application: %s", form.Handle)
	body := fmt.Sprintf("A new membership request has been submitted.\n\nRequest #%d\nDisplay Name: %s\nEmail: %s\nInvite Code: %s\n\nIntroduction:\n%s\n", regID, form.Handle, form.Email, form.InviteCode, form.Introduction)
	s.mailer.Send(email.Message{To: emails, Subject: subject, Body: body})
}

func (s *Server) sendWelcomeEmail(r *http.Request, emailAddr, name, token string) {
	link := s.loginLinkURL(r, token, "")
	if s.mailer != nil && s.mailer.Enabled() {
		subject := fmt.Sprintf("Welcome to dystopian.earth, %s", name)
		body := fmt.Sprintf("Hi %s,\n\nYour membership has been approved! Use this one-time sign-in link to access the member portal: %s\n\nThe link expires in %s. We're glad you're here.\n", name, link, memberLoginTTL.String())
		s.mailer.Send(email.Message{To: []string{emailAddr}, Subject: subject, Body: body})
		return
	}
	log.Printf("welcome link for %s: %s", emailAddr, link)
}

func (s *Server) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": "This approval link is incomplete.",
		})
		return
	}

	hash := sha256.Sum256([]byte(token))
	const query = `SELECT id, user_id, new_email, expires_at FROM email_change_requests WHERE token_hash = ? AND approved_at IS NULL ORDER BY created_at DESC LIMIT 1`
	var (
		requestID int
		userID    int
		newEmail  string
		expires   time.Time
	)
	err := s.db.QueryRowContext(r.Context(), query, hex.EncodeToString(hash[:])).Scan(&requestID, &userID, &newEmail, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": "This approval link has already been used or is invalid.",
		})
		return
	}
	if err != nil {
		log.Printf("load email change: %v", err)
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": "We could not process that approval right now.",
		})
		return
	}
	if time.Now().After(expires) {
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": "This approval link has expired. Submit a new request from the member dashboard.",
		})
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("begin email confirm tx: %v", err)
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": "We could not process that approval right now.",
		})
		return
	}
	defer tx.Rollback()

	var currentEmail string
	if err := tx.QueryRowContext(r.Context(), `SELECT email FROM users WHERE id = ?`, userID).Scan(&currentEmail); err != nil {
		log.Printf("lookup user email: %v", err)
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": "We could not process that approval right now.",
		})
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE users SET fallback_email = email, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, newEmail, userID); err != nil {
		log.Printf("apply email change: %v", err)
		message := "We could not finalize this email change."
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			message = "That email address is already associated with another member."
		}
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": message,
		})
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE email_change_requests SET approved_at = CURRENT_TIMESTAMP WHERE id = ?`, requestID); err != nil {
		log.Printf("mark email change approved: %v", err)
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": "We could not finalize this email change.",
		})
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("commit email change approval: %v", err)
		s.renderTemplate(w, r, "email_confirm.html", map[string]any{
			"Error": "We could not finalize this email change.",
		})
		return
	}

	if s.mailer != nil && s.mailer.Enabled() {
		subject := "Your dystopian.earth email was updated"
		body := fmt.Sprintf("Hello,\n\nYour member email has been updated to %s. The previous address %s has been stored as a fallback contact. If you did not approve this change, reach out to the coordinators immediately.\n", newEmail, currentEmail)
		s.mailer.Send(email.Message{To: []string{newEmail}, Subject: subject, Body: body})
	} else {
		log.Printf("email change confirmed for user %d: %s (fallback %s)", userID, newEmail, currentEmail)
	}

	s.renderTemplate(w, r, "email_confirm.html", map[string]any{
		"Message":       "Email address updated successfully.",
		"NewEmail":      newEmail,
		"PreviousEmail": currentEmail,
	})
}

// Shutdown releases background resources.
func (s *Server) Shutdown() {
	if s.mailer != nil {
		s.mailer.Close()
	}
	if s.redisPool != nil {
		s.redisPool.Close()
	}
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, extra map[string]any) {
	data, err := s.dashboardData(r.Context())
	if err != nil {
		log.Printf("dashboard data: %v", err)
		s.renderError(w, r, http.StatusInternalServerError, "Unable to load dashboard")
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	for k, v := range extra {
		data[k] = v
	}
	s.renderTemplate(w, r, "dashboard.html", data)
}

func (s *Server) dashboardData(ctx context.Context) (map[string]any, error) {
	user := s.currentUser(ctx)
	if user == nil {
		return map[string]any{}, nil
	}
	invites, err := s.memberInvites(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	limit := s.cfg.MaxInvites
	remaining := limit - len(invites)
	if limit <= 0 {
		remaining = -1
		limit = -1
	} else if remaining < 0 {
		remaining = 0
	}
	data := map[string]any{
		"User":             user,
		"Invites":          invites,
		"InviteLimit":      limit,
		"InviteRemaining":  remaining,
		"MailerConfigured": s.mailer != nil && s.mailer.Enabled(),
		"PaymentProviders": paymentProviderOptions,
	}
	pending, err := s.pendingEmailChange(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if pending != nil {
		data["PendingEmailChange"] = pending
	}
	return data, nil
}

type inviteSummary struct {
	Code      string
	CreatedAt time.Time
	UsedAt    *time.Time
}

type emailChangeSummary struct {
	NewEmail  string
	ExpiresAt time.Time
}

type paymentVerificationEntry struct {
	ID        int
	UserID    int
	Name      string
	Email     string
	Provider  string
	Reference string
	CreatedAt time.Time
}

func (s *Server) memberInvites(ctx context.Context, userID int) ([]inviteSummary, error) {
	const query = `SELECT code, created_at, used_at FROM invite_codes WHERE created_by = ? ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []inviteSummary
	for rows.Next() {
		var (
			code     string
			created  time.Time
			usedTime sql.NullTime
		)
		if err := rows.Scan(&code, &created, &usedTime); err != nil {
			return nil, err
		}
		invite := inviteSummary{Code: code, CreatedAt: created}
		if usedTime.Valid {
			t := usedTime.Time
			invite.UsedAt = &t
		}
		invites = append(invites, invite)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return invites, nil
}

func (s *Server) pendingEmailChange(ctx context.Context, userID int) (*emailChangeSummary, error) {
	const query = `SELECT new_email, expires_at FROM email_change_requests WHERE user_id = ? AND approved_at IS NULL ORDER BY created_at DESC LIMIT 1`
	var (
		email   string
		expires time.Time
	)
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&email, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &emailChangeSummary{NewEmail: strings.TrimSpace(email), ExpiresAt: expires}, nil
}

func (s *Server) countMemberInvites(ctx context.Context, userID int) (int, error) {
	const query = `SELECT COUNT(1) FROM invite_codes WHERE created_by = ?`
	var count int
	if err := s.db.QueryRowContext(ctx, query, userID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func generateInviteCode() (string, error) {
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(buf)), nil
}

func randomPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomURLToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Server) emailApprovalURL(r *http.Request, token string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = strings.TrimPrefix(s.cfg.Addr, ":")
		if host == "" {
			host = "localhost"
		} else {
			host = "localhost:" + host
		}
	}
	return fmt.Sprintf("%s://%s/email/confirm?token=%s", scheme, host, url.QueryEscape(token))
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.sessions.GetInt(r.Context(), "user_id") == 0 {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessions.GetInt(r.Context(), "user_id") == 0 {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		handler(w, r)
	}
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.sessions.GetBool(r.Context(), "is_admin") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type user struct {
	ID                 int
	Email              string
	FallbackEmail      string
	Name               string
	Admin              bool
	Bio                string
	PaymentProvider    string
	PaymentRef         string
	DuesCurrent        bool
	OTPSecret          string
	OTPEnabledAt       *time.Time
	SSHPubKey          string
	Introduction       string
	HasLDAPPassword    bool
	HasWireguardConfig bool
	Disabled           bool
}

func (s *Server) currentUser(ctx context.Context) *user {
	id := s.sessions.GetInt(ctx, "user_id")
	if id == 0 {
		return nil
	}

	const query = `SELECT email, fallback_email, display_name, is_admin, bio, payment_provider, payment_ref, dues_current, otp_secret, otp_enabled_at, ssh_pubkey, introduction, ldap_password_encrypted, wireguard_config_encrypted, is_disabled FROM users WHERE id = ?`

	var (
		email      string
		fallback   sql.NullString
		name       string
		admin      int
		bio        string
		provider   string
		paymentRef string
		dues       int
		otpSecret  sql.NullString
		otpEnabled sql.NullTime
		sshKey     sql.NullString
		intro      sql.NullString
		ldapSecret sql.NullString
		wgSecret   sql.NullString
		disabled   int
	)

	err := s.db.QueryRowContext(ctx, query, id).Scan(&email, &fallback, &name, &admin, &bio, &provider, &paymentRef, &dues, &otpSecret, &otpEnabled, &sshKey, &intro, &ldapSecret, &wgSecret, &disabled)
	if err != nil {
		log.Printf("lookup current user: %v", err)
		admin := s.sessions.GetBool(ctx, "is_admin")
		dues := s.sessions.GetBool(ctx, "dues_current")
		if admin {
			dues = true
		}
		return &user{
			ID:          id,
			Email:       s.sessions.GetString(ctx, "email"),
			Name:        s.sessions.GetString(ctx, "display_name"),
			Admin:       admin,
			DuesCurrent: dues,
		}
	}

	u := &user{
		ID:              id,
		Email:           email,
		FallbackEmail:   strings.TrimSpace(fallback.String),
		Name:            name,
		Admin:           admin == 1,
		Bio:             bio,
		PaymentProvider: provider,
		PaymentRef:      paymentRef,
		DuesCurrent:     dues == 1,
		Disabled:        disabled == 1,
	}
	if u.Admin {
		u.DuesCurrent = true
	}
	if otpSecret.Valid {
		u.OTPSecret = strings.TrimSpace(otpSecret.String)
	}
	if otpEnabled.Valid {
		t := otpEnabled.Time
		u.OTPEnabledAt = &t
	}
	if sshKey.Valid {
		u.SSHPubKey = sshKey.String
	}
	if intro.Valid {
		u.Introduction = intro.String
	}
	u.HasLDAPPassword = ldapSecret.Valid && strings.TrimSpace(ldapSecret.String) != ""
	u.HasWireguardConfig = wgSecret.Valid && strings.TrimSpace(wgSecret.String) != ""
	return u
}

func humanizeSlug(slug string) string {
	if slug == "" || slug == "index" {
		return "Home"
	}
	parts := strings.Split(slug, "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}
