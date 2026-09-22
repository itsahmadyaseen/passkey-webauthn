# passkey-webauthn

A FIDO2 / WebAuthn passkey authentication server in Rust — both ceremonies end to end, credentials in PostgreSQL, server-side sessions.

Built on [`webauthn-rs`](https://github.com/kanidm/webauthn-rs) 0.5, Axum 0.8, Tokio and sqlx. Includes a single-page browser client so you can exercise a real passkey login with Touch ID, Windows Hello or a security key.

---

## What it does

Passwords are replaced entirely by a public-key credential held in the user's authenticator. The server never stores a shared secret — only a public key and a signature counter.

- **Registration** — `navigator.credentials.create()` → server verifies the attestation response and stores the credential
- **Authentication** — `navigator.credentials.get()` → server verifies the assertion signature against the stored public key
- **Sessions** — server-side session rows, referenced by an `HttpOnly` cookie
- **Credential management** — list and revoke individual passkeys per user

---

## The two ceremonies

```
REGISTRATION

  Browser                        Server                      PostgreSQL
     │                              │                              │
     │  POST /register/start        │                              │
     │  { username }                │                              │
     │─────────────────────────────>│  find_or_create_user         │
     │                              │─────────────────────────────>│
     │                              │  load existing credential    │
     │                              │  IDs → exclude_credentials   │
     │                              │<─────────────────────────────│
     │                              │                              │
     │  { ceremony_id, options }    │  store ceremony state        │
     │<─────────────────────────────│  (single-use, 60s TTL)       │
     │                              │                              │
     │  navigator.credentials       │                              │
     │    .create(options)          │                              │
     │  ── user gesture ──          │                              │
     │                              │                              │
     │  POST /register/finish       │                              │
     │  { ceremony_id, credential } │                              │
     │─────────────────────────────>│  consume ceremony state      │
     │                              │  verify: challenge, origin,  │
     │                              │  RP ID, type, flags          │
     │                              │  persist passkey             │
     │  { status: "created" }       │─────────────────────────────>│
     │<─────────────────────────────│                              │


AUTHENTICATION

     │  POST /login/start           │                              │
     │  { username }                │  load user's passkeys        │
     │─────────────────────────────>│─────────────────────────────>│
     │  { ceremony_id, options }    │  store ceremony state        │
     │<─────────────────────────────│                              │
     │                              │                              │
     │  navigator.credentials       │                              │
     │    .get(options)             │                              │
     │  ── user gesture ──          │                              │
     │                              │                              │
     │  POST /login/finish          │                              │
     │─────────────────────────────>│  consume ceremony state      │
     │                              │  verify assertion signature, │
     │                              │  challenge, origin, RP ID,   │
     │                              │  UP/UV flags                 │
     │                              │  update sign counter         │
     │  Set-Cookie: session_id      │  create session row          │
     │  { status: "ok" }            │─────────────────────────────>│
     │<─────────────────────────────│                              │
```

The security-critical verification — challenge match, origin match, RP ID hash, credential type, user-presence and user-verification flags, and assertion signature — is performed by `webauthn-rs`. This codebase owns the state machine around it: ceremony storage, single-use enforcement, persistence and sessions.

---

## Quickstart

Requires Rust 1.75+, Docker and a browser with a platform authenticator.

```bash
# 1. Start PostgreSQL
docker compose up -d

# 2. Configure
cp .env.example .env

# 3. Run — migrations apply automatically at startup
cargo run

# 4. Open the demo client
open http://localhost:3000
```

Register a username, approve the passkey prompt, log out, log back in with the passkey.

> `RP_ID` and `RP_ORIGIN` must match the origin you load in the browser **exactly**, or the authenticator will refuse the ceremony. The defaults are `localhost` / `http://localhost:3000`.

---

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | — | Liveness check |
| `POST` | `/register/start` | — | Begin registration, returns creation options |
| `POST` | `/register/finish` | — | Verify attestation, persist the passkey |
| `POST` | `/login/start` | — | Begin authentication, returns request options |
| `POST` | `/login/finish` | — | Verify assertion, create session, set cookie |
| `GET` | `/me` | cookie | Current authenticated user |
| `POST` | `/logout` | cookie | Delete the session row and clear the cookie |
| `GET` | `/credentials` | cookie | List the user's registered passkeys |
| `DELETE` | `/credentials/{id}` | cookie | Revoke one passkey |

---

## Design decisions

**Ceremony state is server-side and single-use.** WebAuthn requires the challenge issued at `start` to be the one verified at `finish`. Storing it client-side would let an attacker choose their own challenge. `ChallengeStore` keys serialized ceremony state by a random `ceremony_id`; `consume()` is load-and-delete, so replaying a `finish` request fails with `CeremonyGone` even inside the 60-second TTL. A background task reaps expired entries every 30 seconds.

**`exclude_credentials` on registration.** Existing credential IDs for the user are passed into the creation options, so an authenticator that is already enrolled declines rather than silently creating a second credential for the same user.

**Sessions are server-side rows, not signed tokens.** A stateless JWT cannot be revoked before it expires. `POST /logout` deletes the row, which invalidates the session immediately. Cookies are `HttpOnly` with `SameSite=Lax`, and a background task clears expired rows every five minutes.

**The ceremony layer holds no Axum types.** `CeremonyService` takes and returns `webauthn-rs` types only, so the protocol logic is testable without standing up an HTTP server.

**Username enumeration on login is deliberately blurred.** `/login/start` returns `Unauthorized` for a user with no registered passkeys rather than a distinguishable "no such user" error.

---

## Not implemented, and why

The list matters more than the feature set — this is a demonstration of the ceremonies, not a production IdP.

| Gap | What production needs |
|---|---|
| **Attestation verification** | Attestation is neither requested nor verified, so any authenticator model is accepted. An enterprise deployment pins an attestation CA list to enforce "only these models". |
| **Signature counter regression policy** | The new counter is persisted, but there is no explicit reject-and-alert on a counter that moves backwards — the signal for a cloned authenticator. |
| **Account recovery** | There is none. Lose every enrolled authenticator and the account is unreachable. Real deployments need a second factor, a recovery code, or an admin path. |
| **`Secure` cookie flag** | Commented out so the demo works over plain HTTP on localhost. Must be on behind TLS. |
| **Horizontal scaling** | `ChallengeStore` is process-local, so two instances behind a load balancer will fail a ceremony that lands on different nodes. Move it to Redis. |
| **Rate limiting** | No throttle on any endpoint. |
| **Tests** | None yet. The highest-value first tests are the replay path (`consume()` twice) and a tampered-challenge assertion. |
| **CI** | No workflow. `cargo clippy -D warnings` and `cargo fmt --check` should gate `main`. |

### Known issues

- **`/login/start` writes on failure.** It calls `find_or_create_user`, so a POST with an unknown username creates a `users` row before returning `Unauthorized`. An unauthenticated caller can grow the table. The lookup should be read-only.
- **`RP_NAME` is ignored.** It is read into `AppConfig` but never used — `ceremony.rs:22` hardcodes `.rp_name("Passkey Auth Demo")`. Wire the config value through.
- **`dashmap` is an unused dependency.** `ChallengeStore` uses `std::sync::Mutex<HashMap<_, _>>`; drop it from `Cargo.toml`.

---

## Layout

```
src/
├── main.rs             # Router, state, migrations, background tasks
├── config.rs           # Env-driven config, fails fast at startup
├── ceremony.rs         # webauthn-rs wrapper — no HTTP types
├── challenge_store.rs  # Single-use, TTL-bounded ceremony state
├── middleware.rs       # AuthUser extractor — validates the session cookie
├── error.rs            # AppError → HTTP status mapping
├── handlers/
│   ├── register.rs     # /register/start · /register/finish
│   ├── login.rs        # /login/start · /login/finish
│   ├── session.rs      # /me · /logout
│   └── credentials.rs  # /credentials · /credentials/{id}
└── db/
    ├── users.rs
    ├── passkeys.rs     # Credential persistence + counter updates
    └── sessions.rs     # Session create / validate / delete / GC
migrations/             # users, passkeys, sessions — applied at startup
static/                 # Single-page demo client
```

## Schema

- **`users`** — `id`, `username` (unique, plus a `LOWER(username)` unique index for case-folded uniqueness), `display_name`
- **`passkeys`** — `credential_id` (unique), the serialized `passkey` as `JSONB`, `sign_count`, `nickname`, `last_used_at`, `ON DELETE CASCADE` from `users`
- **`sessions`** — opaque token as primary key, `expires_at`, `ON DELETE CASCADE` from `users`

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `RP_ID` | — | Required. Relying party ID, e.g. `localhost` |
| `RP_ORIGIN` | — | Required. Must match the browser origin exactly |
| `RP_NAME` | `Passkey Auth` | Currently ignored — see Known issues |
| `DATABASE_URL` | — | Required. PostgreSQL connection string |
| `BIND_ADDRESS` | `0.0.0.0:3000` | |
| `SESSION_TTL_SECS` | `86400` | Session lifetime |
| `RUST_LOG` | `passkey_auth=debug` | `tracing-subscriber` filter |
