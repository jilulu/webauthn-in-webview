// Shared utilities for native Android Credential Manager endpoints.
// The underscore prefix prevents Cloudflare Pages from treating this as a route.

// --- Constants ---

export const KV_CREDS_KEY = 'webauthn-credentials';

export const ALLOWED_ANDROID_HASHES = [
    '32:A2:FC:74:D7:31:10:58:59:E5:A8:5D:F1:6D:95:F1:02:D8:5B:22:09:9B:80:64:C5:D8:91:5C:61:DA:D1:E0',
    '0C:D2:FF:5F:B4:69:C7:8E:FC:B0:D7:5E:31:C6:3C:F7:2E:29:00:2B:2B:AF:71:01:52:51:04:49:B9:9B:2F:F3',
];

export const CORS_HEADERS = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
};

// --- KV helpers ---

export const readCreds = async (kv) => {
    const raw = await kv.get(KV_CREDS_KEY);
    return raw ? JSON.parse(raw) : [];
};

export const writeCreds = async (kv, creds) => {
    await kv.put(KV_CREDS_KEY, JSON.stringify(creds));
};

// --- Base64url / buffer utilities ---
// Direct ports of the same-named functions in script.js.
// atob/btoa are available in the Workers runtime.

export const base64urlToBuffer = (str) => {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad === 2) base64 += '==';
    else if (pad === 3) base64 += '=';
    else if (pad === 1) throw new Error('Invalid base64url string');
    const binaryStr = atob(base64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
    return bytes.buffer;
};

export const bufferToBase64url = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binaryStr = '';
    for (let i = 0; i < bytes.length; i++) binaryStr += String.fromCharCode(bytes[i]);
    return btoa(binaryStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

export const bufferToColonHex = (buffer) =>
    Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0').toUpperCase())
        .join(':');

// --- Crypto helpers ---

/**
 * Converts a DER-encoded ECDSA signature to raw 64-byte (r || s) format.
 * Port of derToRawSignature in script.js — DOM log() calls replaced with throw.
 */
export const derToRawSignature = (derSignature) => {
    const sig = new Uint8Array(derSignature);
    if (sig[0] !== 0x30) throw new Error('DER: Not a sequence');
    let offset = 2; // skip sequence tag + length

    if (sig[offset] !== 0x02) throw new Error('DER: Expected integer for r');
    offset++;
    let rLen = sig[offset++];
    if (sig[offset] === 0x00) { offset++; rLen--; }
    const r = sig.slice(offset, offset + rLen);
    offset += rLen;

    if (sig[offset] !== 0x02) throw new Error('DER: Expected integer for s');
    offset++;
    let sLen = sig[offset++];
    if (sig[offset] === 0x00) { offset++; sLen--; }
    const s = sig.slice(offset, offset + sLen);

    const raw = new Uint8Array(64);
    raw.set(r, 32 - r.length);
    raw.set(s, 64 - s.length);
    return raw.buffer;
};

/**
 * Validates the WebAuthn origin field from clientDataJSON.
 * Port of validateOrigin in script.js adapted for Worker context:
 *   - window.location.origin replaced with explicit expectedWebOrigin param
 *   - log() calls replaced with throw new Error(...)
 *
 * @param {string} receivedOrigin       - The `origin` field from parsed clientDataJSON
 * @param {string} expectedWebOrigin    - e.g. "https://your-pages-domain.pages.dev"
 * @param {string[]} allowedAndroidHashes - colon-hex SHA-256 fingerprints
 */
export const validateOrigin = (receivedOrigin, expectedWebOrigin, allowedAndroidHashes) => {
    if (receivedOrigin === expectedWebOrigin) return;

    if (receivedOrigin.startsWith('android:apk-key-hash:')) {
        const hashBase64 = receivedOrigin.substring('android:apk-key-hash:'.length).trim();
        const hashHex = bufferToColonHex(base64urlToBuffer(hashBase64));
        if (allowedAndroidHashes.includes(hashHex)) return;
        throw new Error(`Android hash not in allowlist: ${hashHex}`);
    }

    throw new Error(`Origin mismatch. Expected: ${expectedWebOrigin} or Android hash. Received: ${receivedOrigin}`);
};

// --- Response helpers ---

export const jsonResponse = (body, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: CORS_HEADERS });

export const errorResponse = (message, status = 400) =>
    jsonResponse({ error: message }, status);

export const optionsResponse = () =>
    new Response(null, { status: 204, headers: CORS_HEADERS });
