package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"dystopian.earth/internal/email"
)

const (
	memberLoginTTL        = time.Hour
	sessionPendingTokenID = "pending_token_id"
	sessionPendingUserID  = "pending_token_user_id"
	sessionPendingHash    = "pending_token_hash"
)

var (
	errInvalidCredentials = errors.New("invalid credentials")
	errInvalidToken       = errors.New("invalid login token")
)

type authUser struct {
	ID          int
	Email       string
	DisplayName string
	Admin       bool
	OTPSecret   string
	DuesCurrent bool
}

type loginTicket struct {
	TokenID    int
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt sql.NullTime
	User       authUser
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = "Sign In"
	data["User"] = s.currentUser(r.Context())
	if _, ok := data["Next"]; !ok {
		next := sanitizeRedirect(r.FormValue("next"), "")
		if next == "" {
			next = sanitizeRedirect(r.URL.Query().Get("next"), "")
		}
		if next != "" {
			data["Next"] = next
		}
	}
	s.renderTemplate(w, r, "auth_login.html", data)
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")

	if email == "" || password == "" {
		s.renderLogin(w, r, map[string]any{
			"Error":     "Email and password are required for admin sign in.",
			"ActiveTab": "admin",
		})
		return
	}

	user, hash, err := s.lookupUserByEmail(r.Context(), email)
	if err != nil {
		s.renderLogin(w, r, map[string]any{
			"Error":     "Invalid credentials.",
			"ActiveTab": "admin",
		})
		return
	}
	if !user.Admin {
		s.renderLogin(w, r, map[string]any{
			"Error":     "Invalid credentials.",
			"ActiveTab": "admin",
		})
		return
	}
	if hash == "" {
		s.renderLogin(w, r, map[string]any{
			"Error":     "Admin account is not configured with a password.",
			"ActiveTab": "admin",
		})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		s.renderLogin(w, r, map[string]any{
			"Error":     "Invalid credentials.",
			"ActiveTab": "admin",
		})
		return
	}

	if err := s.sessions.RenewToken(r.Context()); err != nil {
		log.Printf("renew session token: %v", err)
	}
	s.clearPendingLogin(r.Context())
	s.establishSession(r.Context(), user)

	next := sanitizeRedirect(r.PostFormValue("next"), "/dashboard")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleLoginLinkRequest(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("email"))
	if email == "" {
		s.renderLogin(w, r, map[string]any{
			"Error":      "Enter the email associated with your membership.",
			"ActiveTab":  "members",
			"MemberForm": map[string]string{"Email": email},
		})
		return
	}

	next := sanitizeRedirect(r.PostFormValue("next"), "")

	user, _, err := s.lookupUserByEmail(r.Context(), email)
	if err == nil && !user.Admin {
		token, err := s.createLoginToken(r.Context(), user.ID)
		if err != nil {
			log.Printf("create login token: %v", err)
		} else {
			s.sendLoginLink(r, user.Email, token, next)
		}
	}

	s.renderLogin(w, r, map[string]any{
		"Success":    "If your email is registered, a sign-in link will arrive shortly.",
		"ActiveTab":  "members",
		"MemberForm": map[string]string{"Email": email},
	})
}

func (s *Server) handleOTPVerification(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PostFormValue("otp_code"))
	if code == "" {
		s.renderLogin(w, r, map[string]any{
			"Error":       "Enter the authentication code from your authenticator app.",
			"OTPRequired": true,
			"Email":       s.sessions.GetString(r.Context(), "pending_token_email"),
		})
		return
	}

	tokenID := s.sessions.GetInt(r.Context(), sessionPendingTokenID)
	if tokenID == 0 {
		s.renderLogin(w, r, map[string]any{
			"Error": "That sign-in link is no longer valid. Request a new one.",
		})
		return
	}

	ticket, err := s.lookupLoginTokenByID(r.Context(), tokenID)
	if err != nil {
		s.renderLogin(w, r, map[string]any{
			"Error": "That sign-in link is no longer valid. Request a new one.",
		})
		return
	}
	if !ticket.ConsumedAt.Valid && time.Now().After(ticket.ExpiresAt) {
		s.renderLogin(w, r, map[string]any{
			"Error": "That sign-in link has expired. Request a new one.",
		})
		return
	}
	if ticket.ConsumedAt.Valid {
		s.renderLogin(w, r, map[string]any{
			"Error": "That sign-in link has already been used.",
		})
		return
	}
	if ticket.TokenHash != s.sessions.GetString(r.Context(), sessionPendingHash) {
		s.renderLogin(w, r, map[string]any{
			"Error": "That sign-in link is no longer valid. Request a new one.",
		})
		return
	}
	if ticket.User.OTPSecret == "" {
		s.renderLogin(w, r, map[string]any{
			"Error": "This account does not require an OTP challenge.",
		})
		return
	}
	if !totp.Validate(code, ticket.User.OTPSecret) {
		s.renderLogin(w, r, map[string]any{
			"Error":       "That code was not accepted. Try again.",
			"OTPRequired": true,
			"Email":       ticket.User.Email,
		})
		return
	}

	if err := s.markLoginTokenUsed(r.Context(), ticket.TokenID); err != nil {
		log.Printf("mark login token used: %v", err)
	}
	if err := s.sessions.RenewToken(r.Context()); err != nil {
		log.Printf("renew session token: %v", err)
	}
	s.clearPendingLogin(r.Context())
	s.establishSession(r.Context(), ticket.User)

	next := sanitizeRedirect(r.PostFormValue("next"), "/dashboard")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) completeTokenLogin(w http.ResponseWriter, r *http.Request, token string) {
	ticket, err := s.lookupLoginToken(r.Context(), token)
	if err != nil {
		s.renderLogin(w, r, map[string]any{
			"Error": "That sign-in link is invalid or has expired. Request a new one.",
		})
		return
	}
	if ticket.User.Admin {
		s.renderLogin(w, r, map[string]any{
			"Error": "Administrator accounts must sign in with a password.",
		})
		return
	}
	if ticket.ConsumedAt.Valid {
		s.renderLogin(w, r, map[string]any{
			"Error": "That sign-in link has already been used. Request another one.",
		})
		return
	}
	if time.Now().After(ticket.ExpiresAt) {
		s.renderLogin(w, r, map[string]any{
			"Error": "That sign-in link has expired. Request a new one.",
		})
		return
	}

	if ticket.User.OTPSecret == "" {
		if err := s.markLoginTokenUsed(r.Context(), ticket.TokenID); err != nil {
			log.Printf("mark login token used: %v", err)
		}
		if err := s.sessions.RenewToken(r.Context()); err != nil {
			log.Printf("renew session token: %v", err)
		}
		s.clearPendingLogin(r.Context())
		s.establishSession(r.Context(), ticket.User)

		next := sanitizeRedirect(r.URL.Query().Get("next"), "/dashboard")
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}

	s.sessions.Put(r.Context(), sessionPendingTokenID, ticket.TokenID)
	s.sessions.Put(r.Context(), sessionPendingUserID, ticket.User.ID)
	s.sessions.Put(r.Context(), sessionPendingHash, ticket.TokenHash)
	s.sessions.Put(r.Context(), "pending_token_email", ticket.User.Email)

	s.renderLogin(w, r, map[string]any{
		"OTPRequired": true,
		"Email":       ticket.User.Email,
	})
}

func (s *Server) establishSession(ctx context.Context, user authUser) {
	s.sessions.Put(ctx, "user_id", user.ID)
	s.sessions.Put(ctx, "email", user.Email)
	s.sessions.Put(ctx, "display_name", user.DisplayName)
	s.sessions.Put(ctx, "is_admin", user.Admin)
	s.sessions.Put(ctx, "dues_current", user.DuesCurrent)
}

func (s *Server) clearPendingLogin(ctx context.Context) {
	s.sessions.Remove(ctx, sessionPendingTokenID)
	s.sessions.Remove(ctx, sessionPendingUserID)
	s.sessions.Remove(ctx, sessionPendingHash)
	s.sessions.Remove(ctx, "pending_token_email")
}

func (s *Server) lookupUserByEmail(ctx context.Context, email string) (authUser, string, error) {
	const query = `SELECT id, email, display_name, is_admin, otp_secret, password_hash, dues_current FROM users WHERE email = ?`

	var (
		id          int
		dbEmail     string
		displayName string
		isAdmin     int
		otpSecret   sql.NullString
		password    sql.NullString
		dues        int
	)

	err := s.db.QueryRowContext(ctx, query, email).Scan(&id, &dbEmail, &displayName, &isAdmin, &otpSecret, &password, &dues)
	if err != nil {
		return authUser{}, "", err
	}

	user := authUser{
		ID:          id,
		Email:       dbEmail,
		DisplayName: displayName,
		Admin:       isAdmin == 1,
		DuesCurrent: dues == 1,
	}
	if otpSecret.Valid {
		user.OTPSecret = strings.TrimSpace(otpSecret.String)
	}
	hash := ""
	if password.Valid {
		hash = password.String
	}
	return user, hash, nil
}

func (s *Server) createLoginToken(ctx context.Context, userID int) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	expiresAt := time.Now().Add(memberLoginTTL).UTC()

	if _, err := s.db.ExecContext(ctx, `INSERT INTO login_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)`, userID, hashHex, expiresAt); err != nil {
		return "", err
	}

	// Best-effort clean up of expired tokens.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM login_tokens WHERE (expires_at < CURRENT_TIMESTAMP AND consumed_at IS NULL) OR (consumed_at IS NOT NULL AND consumed_at < DATETIME('now', '-7 days'))`)

	return token, nil
}

func (s *Server) lookupLoginToken(ctx context.Context, token string) (*loginTicket, error) {
	hash := sha256.Sum256([]byte(token))
	return s.lookupLoginTokenByHash(ctx, hex.EncodeToString(hash[:]))
}

func (s *Server) lookupLoginTokenByID(ctx context.Context, id int) (*loginTicket, error) {
	const query = `SELECT lt.id, lt.token_hash, lt.expires_at, lt.consumed_at, u.id, u.email, u.display_name, u.is_admin, u.otp_secret, u.dues_current FROM login_tokens lt JOIN users u ON u.id = lt.user_id WHERE lt.id = ?`

	var (
		tokenID   int
		tokenHash string
		expires   time.Time
		consumed  sql.NullTime
		userID    int
		email     string
		name      string
		admin     int
		otpSecret sql.NullString
		dues      int
	)

	err := s.db.QueryRowContext(ctx, query, id).Scan(&tokenID, &tokenHash, &expires, &consumed, &userID, &email, &name, &admin, &otpSecret, &dues)
	if err != nil {
		return nil, err
	}

	ticket := &loginTicket{
		TokenID:    tokenID,
		TokenHash:  tokenHash,
		ExpiresAt:  expires,
		ConsumedAt: consumed,
		User: authUser{
			ID:          userID,
			Email:       email,
			DisplayName: name,
			Admin:       admin == 1,
			DuesCurrent: dues == 1,
		},
	}
	if otpSecret.Valid {
		ticket.User.OTPSecret = strings.TrimSpace(otpSecret.String)
	}
	return ticket, nil
}

func (s *Server) lookupLoginTokenByHash(ctx context.Context, hash string) (*loginTicket, error) {
	const query = `SELECT lt.id, lt.token_hash, lt.expires_at, lt.consumed_at, u.id, u.email, u.display_name, u.is_admin, u.otp_secret, u.dues_current FROM login_tokens lt JOIN users u ON u.id = lt.user_id WHERE lt.token_hash = ?`

	var (
		tokenID   int
		tokenHash string
		expires   time.Time
		consumed  sql.NullTime
		userID    int
		email     string
		name      string
		admin     int
		otpSecret sql.NullString
		dues      int
	)

	err := s.db.QueryRowContext(ctx, query, hash).Scan(&tokenID, &tokenHash, &expires, &consumed, &userID, &email, &name, &admin, &otpSecret, &dues)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errInvalidToken
		}
		return nil, err
	}

	ticket := &loginTicket{
		TokenID:    tokenID,
		TokenHash:  tokenHash,
		ExpiresAt:  expires,
		ConsumedAt: consumed,
		User: authUser{
			ID:          userID,
			Email:       email,
			DisplayName: name,
			Admin:       admin == 1,
			DuesCurrent: dues == 1,
		},
	}
	if otpSecret.Valid {
		ticket.User.OTPSecret = strings.TrimSpace(otpSecret.String)
	}
	return ticket, nil
}

func (s *Server) markLoginTokenUsed(ctx context.Context, tokenID int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE login_tokens SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?`, tokenID)
	return err
}

func (s *Server) sendLoginLink(r *http.Request, recipient, token, next string) {
	link := s.loginLinkURL(r, token, next)
	if s.mailer != nil && s.mailer.Enabled() {
		subject := "Your dystopian.earth login link"
		body := fmt.Sprintf("Hello!\n\nUse the following link to access your account: %s\n\nThis link expires in %s. If you did not request it, you can ignore this message.\n", link, memberLoginTTL.String())
		s.mailer.Send(email.Message{To: []string{recipient}, Subject: subject, Body: body})
		return
	}
	log.Printf("login link for %s: %s", recipient, link)
}

func (s *Server) loginLinkURL(r *http.Request, token, next string) string {
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

	link := fmt.Sprintf("%s://%s/login?token=%s", scheme, host, url.QueryEscape(token))
	if next != "" {
		link += "&next=" + url.QueryEscape(next)
	}
	return link
}

func sanitizeRedirect(target, fallback string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return fallback
	}
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return fallback
	}
	return target
}
