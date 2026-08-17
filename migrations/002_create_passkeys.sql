CREATE TABLE IF NOT EXISTS passkeys (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   TEXT NOT NULL UNIQUE,
    passkey         JSONB NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    nickname        TEXT NOT NULL DEFAULT 'My Passkey',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys(credential_id);
