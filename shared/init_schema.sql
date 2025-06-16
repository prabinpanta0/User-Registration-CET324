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
    last_failed_login VARCHAR(32) DEFAULT ''
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE blocked_ips (
    ip_address TEXT PRIMARY KEY,
    blocked_until TIMESTAMP WITH TIME ZONE NOT NULL,
    reason TEXT
);