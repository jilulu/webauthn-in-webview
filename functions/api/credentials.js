export async function onRequest(context) {
    const { request, env } = context;
    const KV_KEY = 'webauthn-credentials';

    const readCreds = async () => {
        const raw = await env.PASSKEY_KV.get(KV_KEY);
        return raw ? JSON.parse(raw) : [];
    };

    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers });
    }

    if (request.method === 'GET') {
        const creds = await readCreds();
        return new Response(JSON.stringify(creds), { status: 200, headers });
    }

    if (request.method === 'POST') {
        let newCred;
        try {
            newCred = await request.json();
        } catch {
            return new Response(JSON.stringify({ error: 'Invalid JSON body' }), { status: 400, headers });
        }
        if (!newCred.id || !newCred.username || !newCred.pubKey || newCred.alg === undefined) {
            return new Response(JSON.stringify({ error: 'Missing required fields' }), { status: 422, headers });
        }
        const creds = await readCreds();
        if (!creds.some(c => c.id === newCred.id)) {
            creds.push(newCred);
            await env.PASSKEY_KV.put(KV_KEY, JSON.stringify(creds));
        }
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (request.method === 'DELETE') {
        await env.PASSKEY_KV.delete(KV_KEY);
        return new Response(null, { status: 204, headers });
    }

    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers });
}
