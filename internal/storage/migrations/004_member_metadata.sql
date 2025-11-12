ALTER TABLE users ADD COLUMN ssh_pubkey TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN introduction TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN dues_current INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN ldap_password_encrypted TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN wireguard_config_encrypted TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN wireguard_password_encrypted TEXT DEFAULT '';

ALTER TABLE registrations ADD COLUMN reviewed_by INTEGER;
ALTER TABLE registrations ADD COLUMN reviewed_at TIMESTAMP;
ALTER TABLE registrations ADD COLUMN review_note TEXT DEFAULT '';

ALTER TABLE invite_codes ADD COLUMN created_by INTEGER;

CREATE INDEX IF NOT EXISTS idx_invite_codes_created_by ON invite_codes(created_by);
