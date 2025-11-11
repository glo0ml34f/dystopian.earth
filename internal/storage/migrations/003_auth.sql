ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN otp_secret TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN otp_enabled_at TIMESTAMP;

CREATE TABLE IF NOT EXISTS login_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_login_tokens_user ON login_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_login_tokens_expires ON login_tokens(expires_at);

INSERT INTO users (email, password_hash, display_name, bio, payment_provider, payment_ref, approved_at, is_admin)
SELECT 'admin', '$2a$14$dfZ5u1Mc4tcxWkWOzCX3ZOGtRAvTk/INK3GP3k5U1QIN6hNvRsHMi', 'Administrator', '', '', '', CURRENT_TIMESTAMP, 1
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin');
