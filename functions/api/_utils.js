// Worker-specific utilities for Cloudflare Pages Functions.
// Shared crypto/encoding utilities are imported from /shared/utils.js.

export {
    ALLOWED_ANDROID_HASHES,
    base64urlToBuffer,
    bufferToBase64url,
    bufferToColonHex,
    derToRawSignature,
    validateOrigin,
} from '../../shared/utils.js';

// --- Constants ---

export const KV_CREDS_KEY = 'webauthn-credentials';

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

// --- Response helpers ---

export const jsonResponse = (body, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: CORS_HEADERS });

export const errorResponse = (message, status = 400) =>
    jsonResponse({ error: message }, status);

export const optionsResponse = () =>
    new Response(null, { status: 204, headers: CORS_HEADERS });
