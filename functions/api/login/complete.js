import {
    base64urlToBuffer,
    readCreds,
    validateOrigin, ALLOWED_ANDROID_HASHES,
    derToRawSignature,
    optionsResponse, jsonResponse, errorResponse,
} from '../_utils.js';

export async function onRequest(context) {
    const { request, env } = context;

    if (request.method === 'OPTIONS') return optionsResponse();
    if (request.method !== 'POST') return errorResponse('Method not allowed', 405);

    let body;
    try { body = await request.json(); }
    catch { return errorResponse('Invalid JSON body', 400); }

    const {
        challengeId,
        id, rawId,
        clientDataJSON: clientDataJSONb64,
        authenticatorData: authDatab64,
        signature: signatureb64,
    } = body ?? {};

    if (!challengeId || !id || !rawId || !clientDataJSONb64 || !authDatab64 || !signatureb64) {
        return errorResponse('Missing required fields', 400);
    }

    // Fetch + immediately delete challenge (prevents replay)
    const storedChallenge = await env.PASSKEY_KV.get(`challenge:${challengeId}`);
    if (!storedChallenge) return errorResponse('Challenge expired or invalid', 400);
    await env.PASSKEY_KV.delete(`challenge:${challengeId}`);

    // Parse clientDataJSON — keep the raw bytes for hashing
    let clientData;
    let clientDataJSONBytes;
    try {
        clientDataJSONBytes = base64urlToBuffer(clientDataJSONb64);
        clientData = JSON.parse(new TextDecoder().decode(clientDataJSONBytes));
    } catch {
        return errorResponse('Failed to decode clientDataJSON', 400);
    }

    if (clientData.challenge !== storedChallenge) return errorResponse('Challenge mismatch', 400);
    if (clientData.type !== 'webauthn.get') return errorResponse('Invalid ceremony type', 400);

    const expectedWebOrigin = `https://${new URL(request.url).hostname}`;
    try {
        validateOrigin(clientData.origin, expectedWebOrigin, ALLOWED_ANDROID_HASHES);
    } catch (e) {
        return errorResponse(`Origin validation failed: ${e.message}`, 400);
    }

    // Find credential by rawId
    const creds = await readCreds(env.PASSKEY_KV);
    const cred = creds.find(c => c.rawId === rawId);
    if (!cred) return errorResponse('Credential not found', 404);

    // ES256 only
    if (cred.alg !== -7) return errorResponse(`Unsupported algorithm: ${cred.alg}`, 400);

    // Import SPKI public key
    let publicKey;
    try {
        publicKey = await crypto.subtle.importKey(
            'spki',
            base64urlToBuffer(cred.pubKey),
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['verify']
        );
    } catch (e) {
        return errorResponse(`Failed to import public key: ${e.message}`, 500);
    }

    // Build signature base: authenticatorData || SHA-256(clientDataJSON)
    const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSONBytes);
    const authDataBytes = new Uint8Array(base64urlToBuffer(authDatab64));
    const signatureBase = new Uint8Array([...authDataBytes, ...new Uint8Array(clientDataHash)]);

    // Convert DER signature to raw (r || s)
    let rawSignature;
    try {
        rawSignature = derToRawSignature(base64urlToBuffer(signatureb64));
    } catch (e) {
        return errorResponse(`Failed to parse DER signature: ${e.message}`, 400);
    }

    // Verify
    let valid;
    try {
        valid = await crypto.subtle.verify(
            { name: 'ECDSA', hash: { name: 'SHA-256' } },
            publicKey,
            rawSignature,
            signatureBase.buffer
        );
    } catch (e) {
        return errorResponse(`Internal error: ${e.message}`, 500);
    }

    if (!valid) return errorResponse('Signature verification failed', 401);

    return jsonResponse({ ok: true, username: cred.username });
}
