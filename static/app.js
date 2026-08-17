// ── Passkey Auth — Frontend ──────────────────────────────────────
// Drives navigator.credentials for both registration and authentication.
// Communicates with the Rust/Axum backend via JSON.

// ── DOM references ───────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const usernameInput = $('#username');
const authSection = $('#auth-section');
const dashboardSection = $('#dashboard-section');
const statusEl = $('#status');
const userBadge = $('#user-badge');
const userDisplay = $('#user-display');
const credentialsList = $('#credentials-list');
const btnRegister = $('#btn-register');
const btnLogin = $('#btn-login');

// ── Base64url ↔ ArrayBuffer helpers ──────────────────────────────

/**
 * Decode a base64url-encoded string to a Uint8Array.
 * Handles both base64url and standard base64 (with/without padding).
 */
function base64urlToBuffer(base64url) {
    // Convert base64url → standard base64
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    while (base64.length % 4 !== 0) {
        base64 += '=';
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Encode a BufferSource (ArrayBuffer or Uint8Array) to base64url (no padding).
 */
function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── Status display ───────────────────────────────────────────────

function showStatus(message, type = 'success') {
    statusEl.textContent = message;
    statusEl.className = `status ${type}`;
    statusEl.classList.remove('hidden');

    // Auto-hide after 5 seconds
    clearTimeout(statusEl._timer);
    statusEl._timer = setTimeout(() => {
        statusEl.classList.add('hidden');
    }, 5000);
}

function hideStatus() {
    statusEl.classList.add('hidden');
}

function setLoading(btn, loading) {
    if (loading) {
        btn.classList.add('loading');
        btn.disabled = true;
    } else {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
}

// ── API helpers ──────────────────────────────────────────────────

async function api(method, path, body = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
    };
    if (body) {
        opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.error?.message || `Request failed (${res.status})`);
    }
    return data;
}

// ── Registration ─────────────────────────────────────────────────

async function register() {
    const username = usernameInput.value.trim();
    if (!username) {
        showStatus('Please enter a username.', 'error');
        usernameInput.focus();
        return;
    }

    hideStatus();
    setLoading(btnRegister, true);

    try {
        // Step 1: Start the ceremony
        const startResp = await api('POST', '/register/start', { username });
        const { ceremony_id, options } = startResp;

        // Decode the options for the browser API.
        // The server returns base64url-encoded binary fields; we need ArrayBuffers.
        const publicKey = prepareCreationOptions(options.publicKey);

        // Step 2: Call the browser WebAuthn API
        const credential = await navigator.credentials.create({ publicKey });

        // Step 3: Encode the response and send it back
        const credentialJSON = encodeCreationResponse(credential);

        await api('POST', '/register/finish', {
            ceremony_id,
            credential: credentialJSON,
        });

        showStatus('Passkey created! You can now sign in.', 'success');
    } catch (err) {
        if (err.name === 'NotAllowedError') {
            showStatus('Passkey creation was cancelled.', 'error');
        } else {
            showStatus(err.message || 'Registration failed.', 'error');
        }
        console.error('Registration error:', err);
    } finally {
        setLoading(btnRegister, false);
    }
}

// ── Authentication ───────────────────────────────────────────────

async function login() {
    const username = usernameInput.value.trim();
    if (!username) {
        showStatus('Please enter a username.', 'error');
        usernameInput.focus();
        return;
    }

    hideStatus();
    setLoading(btnLogin, true);

    try {
        // Step 1: Start the ceremony
        const startResp = await api('POST', '/login/start', { username });
        const { ceremony_id, options } = startResp;

        // Decode the options
        const publicKey = prepareRequestOptions(options.publicKey);

        // Step 2: Call the browser WebAuthn API
        const assertion = await navigator.credentials.get({ publicKey });

        // Step 3: Encode and send
        const assertionJSON = encodeAssertionResponse(assertion);

        await api('POST', '/login/finish', {
            ceremony_id,
            credential: assertionJSON,
        });

        showStatus('Signed in!', 'success');
        await checkSession();
    } catch (err) {
        if (err.name === 'NotAllowedError') {
            showStatus('Sign-in was cancelled.', 'error');
        } else {
            showStatus(err.message || 'Sign-in failed.', 'error');
        }
        console.error('Login error:', err);
    } finally {
        setLoading(btnLogin, false);
    }
}

// ── Session management ───────────────────────────────────────────

async function checkSession() {
    try {
        const user = await api('GET', '/me');
        showDashboard(user);
    } catch {
        showAuth();
    }
}

function showDashboard(user) {
    authSection.classList.add('hidden');
    dashboardSection.classList.remove('hidden');
    userBadge.classList.remove('hidden');
    userDisplay.textContent = user.username;
    hideStatus();
    loadCredentials();
}

function showAuth() {
    authSection.classList.remove('hidden');
    dashboardSection.classList.add('hidden');
    userBadge.classList.add('hidden');
    userDisplay.textContent = '';
}

async function logout() {
    try {
        await api('POST', '/logout');
    } catch {
        // Even if the request fails, clear local state
    }
    showAuth();
    showStatus('Signed out.', 'success');
}

// ── Credential management ────────────────────────────────────────

async function loadCredentials() {
    try {
        const creds = await api('GET', '/credentials');
        renderCredentials(creds);
    } catch (err) {
        credentialsList.innerHTML = '<div class="empty-state">Failed to load credentials.</div>';
    }
}

function renderCredentials(creds) {
    if (creds.length === 0) {
        credentialsList.innerHTML = '<div class="empty-state">No passkeys registered yet.</div>';
        return;
    }

    credentialsList.innerHTML = creds.map(cred => {
        const created = new Date(cred.created_at).toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric'
        });
        const lastUsed = cred.last_used_at
            ? new Date(cred.last_used_at).toLocaleDateString('en-US', {
                year: 'numeric', month: 'short', day: 'numeric'
            })
            : 'Never';

        return `
            <div class="credential-card" id="cred-${cred.id}">
                <div class="credential-info">
                    <span class="credential-name">${escapeHtml(cred.nickname)}</span>
                    <div class="credential-meta">
                        <span>Created: ${created}</span>
                        <span>Last used: ${lastUsed}</span>
                        <span>Counter: ${cred.sign_count}</span>
                    </div>
                </div>
                <button class="btn btn-danger btn-sm" onclick="deleteCredential('${cred.id}')">
                    Revoke
                </button>
            </div>
        `;
    }).join('');
}

async function deleteCredential(id) {
    if (!confirm('Revoke this passkey? This cannot be undone.')) return;

    try {
        await api('DELETE', `/credentials/${id}`);
        const el = document.getElementById(`cred-${id}`);
        if (el) {
            el.style.opacity = '0';
            el.style.transform = 'translateX(20px)';
            el.style.transition = 'all 0.3s ease';
            setTimeout(() => el.remove(), 300);
        }
        // Reload after animation
        setTimeout(loadCredentials, 400);
    } catch (err) {
        showStatus(err.message || 'Failed to revoke passkey.', 'error');
    }
}

async function registerAdditional() {
    // Get the current user's username from the badge
    const username = userDisplay.textContent;
    if (!username) return;

    try {
        const startResp = await api('POST', '/register/start', { username });
        const { ceremony_id, options } = startResp;
        const publicKey = prepareCreationOptions(options.publicKey);
        const credential = await navigator.credentials.create({ publicKey });
        const credentialJSON = encodeCreationResponse(credential);

        await api('POST', '/register/finish', {
            ceremony_id,
            credential: credentialJSON,
        });

        showStatus('New passkey added!', 'success');
        loadCredentials();
    } catch (err) {
        if (err.name === 'NotAllowedError') {
            showStatus('Passkey creation was cancelled.', 'error');
        } else {
            showStatus(err.message || 'Failed to add passkey.', 'error');
        }
    }
}

// ── WebAuthn encoding helpers ────────────────────────────────────

/**
 * Prepare PublicKeyCredentialCreationOptions from the server response.
 * Converts base64url strings to ArrayBuffers where the browser API expects them.
 */
function prepareCreationOptions(opts) {
    const publicKey = { ...opts };

    // challenge: base64url → ArrayBuffer
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);

    // user.id: base64url → ArrayBuffer
    if (publicKey.user && publicKey.user.id) {
        publicKey.user = {
            ...publicKey.user,
            id: base64urlToBuffer(publicKey.user.id),
        };
    }

    // excludeCredentials[].id: base64url → ArrayBuffer
    if (publicKey.excludeCredentials) {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map(cred => ({
            ...cred,
            id: base64urlToBuffer(cred.id),
        }));
    }

    return publicKey;
}

/**
 * Prepare PublicKeyCredentialRequestOptions from the server response.
 */
function prepareRequestOptions(opts) {
    const publicKey = { ...opts };

    publicKey.challenge = base64urlToBuffer(publicKey.challenge);

    if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
            ...cred,
            id: base64urlToBuffer(cred.id),
        }));
    }

    return publicKey;
}

/**
 * Encode a PublicKeyCredential (registration response) for the server.
 */
function encodeCreationResponse(cred) {
    const response = cred.response;
    return {
        id: cred.id,
        rawId: bufferToBase64url(cred.rawId),
        type: cred.type,
        response: {
            attestationObject: bufferToBase64url(response.attestationObject),
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
        },
    };
}

/**
 * Encode a PublicKeyCredential (authentication response) for the server.
 */
function encodeAssertionResponse(cred) {
    const response = cred.response;
    return {
        id: cred.id,
        rawId: bufferToBase64url(cred.rawId),
        type: cred.type,
        response: {
            authenticatorData: bufferToBase64url(response.authenticatorData),
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            signature: bufferToBase64url(response.signature),
            userHandle: response.userHandle
                ? bufferToBase64url(response.userHandle)
                : null,
        },
    };
}

/**
 * Basic HTML escaping to prevent XSS in rendered credential names.
 */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ── Handle Enter key ──────────────────────────────────────────────
usernameInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        login();
    }
});

// ── Check session on page load ───────────────────────────────────
checkSession();
