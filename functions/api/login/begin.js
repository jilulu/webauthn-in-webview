import { bufferToBase64url, optionsResponse, jsonResponse, errorResponse } from '../_utils.js';

export async function onRequest(context) {
    const { request, env } = context;

    if (request.method === 'OPTIONS') return optionsResponse();
    if (request.method !== 'POST') return errorResponse('Method not allowed', 405);

    const rpId = new URL(request.url).hostname;

    const challenge = bufferToBase64url(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const challengeId = bufferToBase64url(crypto.getRandomValues(new Uint8Array(16)).buffer);

    await env.PASSKEY_KV.put(`challenge:${challengeId}`, challenge, { expirationTtl: 300 });

    return jsonResponse({
        challengeId,
        challenge,
        rpId,
        userVerification: 'required',
        timeout: 60000,
    });
}
