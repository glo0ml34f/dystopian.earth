package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type joinForm struct {
	Handle       string
	Email        string
	InviteCode   string
	SSHPubKey    string
	Introduction string
}

func (s *Server) getJoin(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Title":            "Join the Collective",
		"Form":             joinForm{},
		"InviteTTLMinutes": int(s.inviteJWT.Lifetime().Minutes()),
		"InviteTTLSeconds": int(s.inviteJWT.Lifetime().Seconds()),
		"User":             s.currentUser(r.Context()),
	}
	s.renderTemplate(w, r, "join.html", data)
}

func (s *Server) postJoin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderTemplate(w, r, "join.html", map[string]any{
			"Title":            "Join the Collective",
			"Error":            "Unable to read submission. Please try again.",
			"Form":             joinForm{},
			"InviteTTLMinutes": int(s.inviteJWT.Lifetime().Minutes()),
			"InviteTTLSeconds": int(s.inviteJWT.Lifetime().Seconds()),
			"User":             s.currentUser(r.Context()),
		})
		return
	}

	form := joinForm{
		Handle:       strings.TrimSpace(r.FormValue("display_name")),
		Email:        strings.TrimSpace(r.FormValue("email")),
		InviteCode:   strings.TrimSpace(r.FormValue("invite_code")),
		SSHPubKey:    strings.TrimSpace(r.FormValue("ssh_pubkey")),
		Introduction: strings.TrimSpace(r.FormValue("introduction")),
	}

	errs := validateJoinForm(r.Context(), s, form)
	if len(errs) > 0 {
		s.renderTemplate(w, r, "join.html", map[string]any{
			"Title":            "Join the Collective",
			"Error":            strings.Join(errs, " "),
			"Form":             form,
			"InviteTTLMinutes": int(s.inviteJWT.Lifetime().Minutes()),
			"InviteTTLSeconds": int(s.inviteJWT.Lifetime().Seconds()),
			"User":             s.currentUser(r.Context()),
		})
		return
	}

	regID, err := s.saveJoinRequest(r.Context(), form)
	if err != nil {
		s.renderTemplate(w, r, "join.html", map[string]any{
			"Title":            "Join the Collective",
			"Error":            "Failed to record your request. Please retry soon.",
			"Form":             form,
			"InviteTTLMinutes": int(s.inviteJWT.Lifetime().Minutes()),
			"InviteTTLSeconds": int(s.inviteJWT.Lifetime().Seconds()),
			"User":             s.currentUser(r.Context()),
		})
		return
	}

	s.notifyAdminsOfRegistration(r.Context(), regID, form)

	s.renderTemplate(w, r, "join.html", map[string]any{
		"Title":            "Join the Collective",
		"Success":          "Request received. Our moderators will contact you after review.",
		"Form":             joinForm{},
		"InviteTTLMinutes": int(s.inviteJWT.Lifetime().Minutes()),
		"InviteTTLSeconds": int(s.inviteJWT.Lifetime().Seconds()),
		"User":             s.currentUser(r.Context()),
	})
}

func validateJoinForm(ctx context.Context, s *Server, form joinForm) []string {
	var errs []string

	if form.Handle == "" {
		errs = append(errs, "Handle is required.")
	} else if len([]rune(form.Handle)) < 2 || len([]rune(form.Handle)) > 32 {
		errs = append(errs, "Handle must be between 2 and 32 characters.")
	}

	if form.Email == "" {
		errs = append(errs, "Email is required.")
	} else if _, err := mail.ParseAddress(form.Email); err != nil {
		errs = append(errs, "Provide a valid email address.")
	}

	if form.InviteCode == "" {
		errs = append(errs, "Invite code or freshly minted invite token is required.")
	} else if len(form.InviteCode) > 1024 {
		errs = append(errs, "Invite code is unexpectedly long.")
	} else if strings.Count(form.InviteCode, ".") == 2 {
		claims, err := s.inviteJWT.Validate(form.InviteCode)
		if err != nil {
			errs = append(errs, "Invite token is invalid or has expired.")
		} else {
			handleClaim, _ := claims["handle"].(string)
			emailClaim, _ := claims["email"].(string)
			if handleClaim != form.Handle {
				errs = append(errs, "Invite token handle does not match your submission.")
			}
			if !strings.EqualFold(emailClaim, form.Email) {
				errs = append(errs, "Invite token email does not match your submission.")
			}
		}
	} else {
		ok, err := s.inviteCodeAvailable(ctx, form.InviteCode)
		if err != nil {
			errs = append(errs, "Unable to validate that invite code right now.")
		} else if !ok {
			errs = append(errs, "That invite code has already been used or has expired.")
		}
	}

	if form.Introduction == "" {
		errs = append(errs, "Share a short introduction about your interests or skills.")
	} else if len([]rune(form.Introduction)) > 1200 {
		errs = append(errs, "Introduction must be 1200 characters or fewer.")
	}

	if len(form.SSHPubKey) > 0 && len(form.SSHPubKey) > 4096 {
		errs = append(errs, "SSH public key is too long.")
	}

	return errs
}

func (s *Server) saveJoinRequest(ctx context.Context, form joinForm) (int64, error) {
	const stmt = `INSERT INTO registrations (email, display_name, invite_code, challenge_answer, ssh_pubkey, introduction)
VALUES (?, ?, ?, ?, ?, ?)`

	res, err := s.db.ExecContext(ctx, stmt, form.Email, form.Handle, form.InviteCode, form.Introduction, nullIfEmpty(form.SSHPubKey), form.Introduction)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Server) inviteCodeAvailable(ctx context.Context, code string) (bool, error) {
	const query = `SELECT used_at, expires_at FROM invite_codes WHERE code = ?`
	var used sql.NullTime
	var expires sql.NullTime
	err := s.db.QueryRowContext(ctx, query, code).Scan(&used, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if used.Valid {
		return false, nil
	}
	if expires.Valid && time.Now().After(expires.Time) {
		return false, nil
	}
	return true, nil
}

type flagMintRequest struct {
	Flag   string `json:"flag"`
	Handle string `json:"handle"`
	Email  string `json:"email"`
}

type flagMintResponse struct {
	InviteCode string `json:"invite_code"`
	ExpiresAt  string `json:"expires_at"`
}

func (s *Server) postJoinFlag(w http.ResponseWriter, r *http.Request) {
	limited := http.MaxBytesReader(w, r.Body, 4096)
	defer limited.Close()

	var req flagMintRequest
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}

	handle := strings.TrimSpace(req.Handle)
	email := strings.TrimSpace(req.Email)
	flag := strings.TrimSpace(req.Flag)

	if handle == "" || email == "" || flag == "" {
		http.Error(w, "flag, handle, and email are required", http.StatusBadRequest)
		return
	}
	if _, err := mail.ParseAddress(email); err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}
	if !s.verifyFlag(flag) {
		http.Error(w, "flag rejected", http.StatusUnauthorized)
		return
	}

	token, expiresAt, err := s.inviteJWT.Mint(handle, email)
	if err != nil {
		http.Error(w, "could not mint invite token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := flagMintResponse{InviteCode: token, ExpiresAt: expiresAt.Format(time.RFC3339)}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func (s *Server) verifyFlag(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}

	day := dailySeed(time.Now().UTC())
	if strings.EqualFold(candidate, dailyFlag(s.cfg.FlagSecret, "hacker", day)) {
		return true
	}
	if strings.EqualFold(candidate, dailyFlag(s.cfg.FlagSecret, "artist", day)) {
		return true
	}
	site, _ := selectSite(day, s.cfg.FlagSecret)
	return strings.EqualFold(candidate, site.Name)
}

type inviteTokenManager struct {
	mu           sync.Mutex
	current      []byte
	previous     []byte
	lastRotation time.Time
	nextRotation time.Time
	ttl          time.Duration
}

func newInviteTokenManager(ttl time.Duration) (*inviteTokenManager, error) {
	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &inviteTokenManager{
		current:      secret,
		lastRotation: now,
		nextRotation: dailySeed(now).Add(24 * time.Hour),
		ttl:          ttl,
	}, nil
}

func (m *inviteTokenManager) Lifetime() time.Duration {
	return m.ttl
}

func (m *inviteTokenManager) Mint(handle, email string) (string, time.Time, error) {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureFreshLocked(now); err != nil {
		return "", time.Time{}, err
	}

	expiresAt := now.Add(m.ttl)
	claims := jwt.MapClaims{
		"handle": handle,
		"email":  email,
		"aud":    "dystopian.earth",
		"iat":    jwt.NewNumericDate(now),
		"exp":    jwt.NewNumericDate(expiresAt),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.current)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (m *inviteTokenManager) Validate(token string) (jwt.MapClaims, error) {
	now := time.Now().UTC()
	m.mu.Lock()
	if err := m.ensureFreshLocked(now); err != nil {
		m.mu.Unlock()
		return nil, err
	}

	current := make([]byte, len(m.current))
	copy(current, m.current)
	var previous []byte
	if len(m.previous) > 0 {
		previous = make([]byte, len(m.previous))
		copy(previous, m.previous)
	}
	m.mu.Unlock()

	if claims, err := parseInviteToken(token, current); err == nil {
		return claims, nil
	} else if previous != nil {
		if claims, errPrev := parseInviteToken(token, previous); errPrev == nil {
			return claims, nil
		}
	}

	return nil, errors.New("invalid invite token")
}

func (m *inviteTokenManager) ensureFreshLocked(now time.Time) error {
	if len(m.previous) > 0 && now.Sub(m.lastRotation) > m.ttl {
		zeroBytes(m.previous)
		m.previous = nil
	}

	if now.Before(m.nextRotation) {
		return nil
	}

	secret, err := generateSecret()
	if err != nil {
		return err
	}

	if len(m.current) > 0 {
		if len(m.previous) > 0 {
			zeroBytes(m.previous)
		}
		m.previous = make([]byte, len(m.current))
		copy(m.previous, m.current)
	}

	m.current = secret
	m.lastRotation = now
	m.nextRotation = dailySeed(now).Add(24 * time.Hour)
	return nil
}

func generateSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	return secret, nil
}

func parseInviteToken(token string, secret []byte) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithAudience("dystopian.earth"),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	claims := jwt.MapClaims{}
	parsed, err := parser.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	if handle, ok := claims["handle"].(string); !ok || strings.TrimSpace(handle) == "" {
		return nil, errors.New("missing handle claim")
	} else {
		claims["handle"] = handle
	}
	if email, ok := claims["email"].(string); !ok || strings.TrimSpace(email) == "" {
		return nil, errors.New("missing email claim")
	} else {
		claims["email"] = email
	}
	return claims, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
