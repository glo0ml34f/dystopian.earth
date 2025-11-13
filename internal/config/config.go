package config

import (
	"encoding/base64"
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds application configuration.
type Config struct {
	Addr          string
	DSN           string
	RedisAddr     string
	RedisPassword string
	SessionTTL    time.Duration
	InviteSecret  string
	FlagSecret    string
	ContentDir    string
	TemplatesDir  string
	StaticDir     string
	SMTPHost      string
	SMTPPort      int
	SMTPUsername  string
	SMTPToken     string
	SMTPUseTLS    bool
	EmailFrom     string
	AdminEmail    string
	TorSOCKS      string
	TorControl    string
	EncryptionKey []byte
	MaxInvites    int
}

// FromEnv loads configuration from environment variables and applies sensible defaults.
func FromEnv() Config {
	cfg := Config{
		Addr:          getEnv("PORTAL_ADDR", ":8080"),
		DSN:           getEnv("PORTAL_DSN", "file:portal.db?_pragma=foreign_keys(ON)"),
		RedisAddr:     getEnv("PORTAL_REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword: getEnv("PORTAL_REDIS_PASSWORD", ""),
		InviteSecret:  getEnv("PORTAL_INVITE_SECRET", "change-me"),
		FlagSecret:    getEnv("PORTAL_FLAG_SECRET", "rotate-me"),
		ContentDir:    getEnv("PORTAL_CONTENT_DIR", "content"),
		TemplatesDir:  getEnv("PORTAL_TEMPLATES_DIR", "web/templates"),
		StaticDir:     getEnv("PORTAL_STATIC_DIR", "web/static"),
		SMTPHost:      getEnv("PORTAL_SMTP_HOST", ""),
		SMTPPort:      MustEnvInt("PORTAL_SMTP_PORT", 0),
		SMTPUsername:  getEnv("PORTAL_SMTP_USERNAME", ""),
		SMTPToken:     getEnv("PORTAL_SMTP_TOKEN", ""),
		SMTPUseTLS:    getEnv("PORTAL_SMTP_TLS", "true") != "false",
		EmailFrom:     getEnv("PORTAL_EMAIL_FROM", ""),
		AdminEmail:    getEnv("PORTAL_ADMIN_EMAIL", ""),
		TorSOCKS:      getEnv("PORTAL_TOR_SOCKS", ""),
		TorControl:    getEnv("PORTAL_TOR_CONTROL", ""),
		MaxInvites:    MustEnvInt("PORTAL_MEMBER_INVITES", 10),
	}

	ttl := getEnv("PORTAL_SESSION_TTL", "720h")
	d, err := time.ParseDuration(ttl)
	if err != nil {
		log.Printf("invalid PORTAL_SESSION_TTL %q, defaulting to 720h: %v", ttl, err)
		d = 720 * time.Hour
	}
	cfg.SessionTTL = d

	key := getEnv("PORTAL_ENCRYPTION_KEY", "")
	if key != "" {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			log.Printf("invalid PORTAL_ENCRYPTION_KEY: %v", err)
		} else if len(decoded) != 32 {
			log.Printf("PORTAL_ENCRYPTION_KEY must decode to 32 bytes, got %d", len(decoded))
		} else {
			cfg.EncryptionKey = decoded
		}
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// MustEnvInt fetches an int value from env with fallback.
func MustEnvInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Printf("invalid value for %s: %v", key, err)
			return fallback
		}
		return i
	}
	return fallback
}
