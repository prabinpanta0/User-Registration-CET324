CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    -- password_salt: Legacy salt for SHA256. For Argon2id, salt is part of password_hash.
    -- This column is being phased out. Will be set to NULL or empty for Argon2id users.
    -- TODO: Plan for eventual removal of this column after sufficient migration period.
    password_salt VARCHAR(64) NULL DEFAULT NULL,
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

CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    csrf_token TEXT DEFAULT '' -- Store CSRF token associated with the session
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip_address TEXT PRIMARY KEY,
    blocked_until TIMESTAMP WITH TIME ZONE NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS captcha_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    ip_address TEXT NOT NULL,
    solution VARCHAR(10) NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- DEPRECATION AND REMOVAL STRATEGY FOR password_salt:
--
-- The `password_salt` column in the `users` table is deprecated as of [Date of Change - e.g., YYYY-MM-DD].
-- It was used for legacy SHA256 password hashing. With the introduction of Argon2id,
-- the salt is included directly within the `password_hash` string.
--
-- For new users and users migrated to Argon2id, this column will be set to NULL (or an empty string
-- if the application logic inserts empty strings into nullable VARCHAR columns, though NULL is preferred).
--
-- Existing Installations:
-- After a sufficient migration period (e.g., 3-6 months, depending on user activity)
-- to allow most active users to log in and have their passwords transparently migrated
-- to Argon2id, this column can be considered for removal.
--
-- Steps to Remove `password_salt` (after migration period):
-- 1. Confirm Data Migration:
--    Ensure that all (or a vast majority of) user rows have had their `password_salt`
--    cleared (set to NULL or empty string). This can be checked with a query like:
--    `SELECT COUNT(*) FROM users WHERE password_salt IS NOT NULL AND password_salt != '';`
--    If there are still users with legacy salts, assess if they are active or if
--    manual intervention for their migration is acceptable.
--
-- 2. Application Code Update (if not already done):
--    Ensure no part of the application code actively relies on reading `password_salt`
--    for new hashing/verification logic (it should only be used by the legacy verification path).
--    The user object/model might also need adjustment if it strictly expects a non-null salt.
--
-- 3. Database Schema Change:
--    Execute the following SQL command to remove the column:
--    `ALTER TABLE users DROP COLUMN password_salt;`
--
-- 4. Testing:
--    Thoroughly test user registration, login (for both Argon2id and any remaining legacy users if the
--    legacy path is kept longer), and password change functionalities after the schema change.
--
-- Note: The exact timing for removal should be based on monitoring user logins and the
-- proportion of passwords migrated. Communication with users regarding password security
-- updates might also be part of the strategy.