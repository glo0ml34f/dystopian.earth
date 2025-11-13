ALTER TABLE users ADD COLUMN fallback_email TEXT DEFAULT '';

UPDATE users SET fallback_email = email WHERE fallback_email = '';
UPDATE users SET email = email || '@localhost' WHERE email NOT LIKE '%@%' AND is_admin = 1;

CREATE TABLE IF NOT EXISTS email_change_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    new_email TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    requested_by_admin INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    approved_at TIMESTAMP,
    approved_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_email_change_requests_user
    ON email_change_requests(user_id)
    WHERE approved_at IS NULL;

CREATE TABLE IF NOT EXISTS payment_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    reference TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP,
    reviewed_by INTEGER,
    note TEXT DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_payment_verifications_status
    ON payment_verifications(status, created_at);
