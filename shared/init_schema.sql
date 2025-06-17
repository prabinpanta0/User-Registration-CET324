CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    password_salt VARCHAR(64) NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_enc TEXT,         -- AES-GCM encrypted TOTP secret
    mfa_iv VARCHAR(32),          -- IV for mfa_secret_enc
    recovery_codes_enc TEXT,     -- AES-GCM encrypted recovery codes (optional)
    last_login VARCHAR(32),      -- ISO timestamp or similar
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    lockout_until VARCHAR(32) DEFAULT '',
    last_failed_login VARCHAR(32) DEFAULT '',
    password_history JSONB DEFAULT '[]'::jsonb,
    password_last_changed TIMESTAMPTZ DEFAULT NOW(),
    is_verified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    csrf_token TEXT DEFAULT '' -- Store CSRF token associated with the session
);

CREATE TABLE blocked_ips (
    ip_address TEXT PRIMARY KEY,
    blocked_until TIMESTAMP WITH TIME ZONE NOT NULL, -- Or TIMESTAMPTZ, they are equivalent in behavior
    reason TEXT
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, -- Keep audit even if user is deleted
    client_ip VARCHAR(45), -- Accommodate IPv6
    user_agent TEXT,
    data JSONB, -- For non-sensitive, searchable details
    iv TEXT, -- Store as hex string from AES GCM
    encrypted_details TEXT, -- Store as hex string (ciphertext)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);