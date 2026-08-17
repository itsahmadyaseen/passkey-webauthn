CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enforce case-folded uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users (LOWER(username));
