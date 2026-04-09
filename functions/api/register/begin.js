import { bufferToBase64url, optionsResponse, jsonResponse, errorResponse } from '../_utils.js';

export async function onRequest(context) {
    const { request, env } = context;

    if (request.method === 'OPTIONS') return optionsResponse();
    if (request.method !== 'POST') return errorResponse('Method not allowed', 405);

    let body;
    try { body = await request.json(); }
    catch { return errorResponse('Invalid JSON body', 400); }

    const username = body?.username?.trim();
    if (!username) return errorResponse('Missing required field: username', 422);

    const rpId = new URL(request.url).hostname;

    const challenge = bufferToBase64url(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const challengeId = bufferToBase64url(crypto.getRandomValues(new Uint8Array(16)).buffer);
    const userId = bufferToBase64url(crypto.getRandomValues(new Uint8Array(16)).buffer);

    await env.PASSKEY_KV.put(`challenge:${challengeId}`, challenge, { expirationTtl: 300 });

    return jsonResponse({
        challengeId,
        challenge,
        rp: { name: 'WebAuthn Demo', id: rpId },
        user: { id: userId, name: username, displayName: username },
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'required',
        },
        timeout: 60000,
        attestation: 'none',
    });
}
