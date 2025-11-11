package server

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexedwards/scs/redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gomodule/redigo/redis"

	"dystopian.earth/internal/config"
	"dystopian.earth/internal/markdown"
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

	return &Server{
		cfg:       cfg,
		db:        db,
		sessions:  session,
		templates: templates,
		renderer:  renderer,
		contentFS: content,
		redisPool: pool,
		inviteJWT: tokens,
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
		protected.Post("/payment", s.updatePayment)
	})

	r.Group(func(admin chi.Router) {
		admin.Use(s.authMiddleware)
		admin.Use(s.requireAdmin)
		admin.Get("/admin/registrations", s.listRegistrations)
		admin.Post("/admin/registrations/{id}/approve", s.approveRegistration)
		admin.Post("/admin/registrations/{id}/reject", s.rejectRegistration)
		admin.Get("/admin/invites", s.listInvites)
		admin.Post("/admin/invites", s.createInvite)
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
	s.renderTemplate(w, r, "dashboard.html", map[string]any{
		"User": s.currentUser(r.Context()),
	})
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "dashboard.html", map[string]any{
		"Message": "profile update stub",
		"User":    s.currentUser(r.Context()),
	})
}

func (s *Server) updatePayment(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "dashboard.html", map[string]any{
		"Message": "payment update stub",
		"User":    s.currentUser(r.Context()),
	})
}

func (s *Server) listRegistrations(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "admin_registrations.html", map[string]any{})
}

func (s *Server) approveRegistration(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rejectRegistration(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listInvites(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, "admin_invites.html", map[string]any{})
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
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
	ID    int
	Email string
	Name  string
	Admin bool
}

func (s *Server) currentUser(ctx context.Context) *user {
	id := s.sessions.GetInt(ctx, "user_id")
	if id == 0 {
		return nil
	}
	return &user{
		ID:    id,
		Email: s.sessions.GetString(ctx, "email"),
		Name:  s.sessions.GetString(ctx, "display_name"),
		Admin: s.sessions.GetBool(ctx, "is_admin"),
	}
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
