import {
    base64urlToBuffer,
    readCreds, writeCreds,
    validateOrigin, ALLOWED_ANDROID_HASHES,
    optionsResponse, jsonResponse, errorResponse,
} from '../_utils.js';

export async function onRequest(context) {
    const { request, env } = context;

    if (request.method === 'OPTIONS') return optionsResponse();
    if (request.method !== 'POST') return errorResponse('Method not allowed', 405);

    let body;
    try { body = await request.json(); }
    catch { return errorResponse('Invalid JSON body', 400); }

    const { challengeId, id, rawId, clientDataJSON: clientDataJSONb64, pubKey, alg, username } = body ?? {};
    if (!challengeId || !id || !rawId || !clientDataJSONb64 || !pubKey || alg === undefined || !username) {
        return errorResponse('Missing required fields', 400);
    }

    // Fetch + immediately delete challenge (prevents replay)
    const storedChallenge = await env.PASSKEY_KV.get(`challenge:${challengeId}`);
    if (!storedChallenge) return errorResponse('Challenge expired or invalid', 400);
    await env.PASSKEY_KV.delete(`challenge:${challengeId}`);

    // Parse clientDataJSON
    let clientData;
    try {
        const bytes = base64urlToBuffer(clientDataJSONb64);
        clientData = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
        return errorResponse('Failed to decode clientDataJSON', 400);
    }

    if (clientData.challenge !== storedChallenge) return errorResponse('Challenge mismatch', 400);
    if (clientData.type !== 'webauthn.create') return errorResponse('Invalid ceremony type', 400);

    const expectedWebOrigin = `https://${new URL(request.url).hostname}`;
    try {
        validateOrigin(clientData.origin, expectedWebOrigin, ALLOWED_ANDROID_HASHES);
    } catch (e) {
        return errorResponse(`Origin validation failed: ${e.message}`, 400);
    }

    // Store credential (deduplicate by id)
    const creds = await readCreds(env.PASSKEY_KV);
    if (!creds.some(c => c.id === id)) {
        creds.push({ username, id, rawId, pubKey, alg });
        await writeCreds(env.PASSKEY_KV, creds);
    }

    return jsonResponse({ ok: true });
}
