import { ALLOWED_ANDROID_HASHES, base64urlToBuffer, bufferToBase64url, bufferToColonHex, derToRawSignature, validateOrigin } from '/shared/utils.js';

document.addEventListener('DOMContentLoaded', () => {
    // --- Configuration ---
    // The URL for the related origins request.
    // See https://github.com/deephand/netlify-related-origin for the configuration.
    const RELATED_ORIGIN = 'deephand-related-origin.netlify.app';

    // --- DOM Elements ---
    const statusContainer = document.getElementById('status-checks');
    const getAssertionBtn = document.getElementById('get-assertion-btn');
    const createCredentialBtn = document.getElementById('create-credential-btn');
    const usernameInput = document.getElementById('username-input');
    const logDisplay = document.getElementById('log-display');
    const credentialsListDiv = document.getElementById('credentials-list');
    const clearStorageBtn = document.getElementById('clear-storage-btn');
    const relatedOriginsCheckbox = document.getElementById('related-origins-checkbox');

    // --- Utility Functions ---

    /**
     * Logs messages to the on-screen console.
     * @param {string} title The title of the log entry.
     * @param {any} data The data to log (will be stringified).
     * @param {'success' | 'error' | 'info'} type The type of log entry for color coding.
     */
    const log = (title, data = '', type = 'info') => {
        const now = new Date().toLocaleTimeString();
        let color = 'text-gray-400';
        if (type === 'success') color = 'text-green-400';
        if (type === 'error') color = 'text-red-400';
        
        const dataStr = data ? `\n${JSON.stringify(data, null, 2)}` : '';
        const currentLog = logDisplay.innerHTML;
        logDisplay.innerHTML = `[${now}] <span class="${color}">${title}</span>${dataStr}\n\n${currentLog}`;
    };

    /**
     * Renders a status item in the UI.
     * @param {string} label The text label for the check.
     * @param {boolean} success Whether the check passed.
     * @param {string} [notes=''] Optional notes to display below the status.
     */
    const renderStatus = (label, success, notes = '') => {
        const status = success ? 'success' : 'failure';
        const badgeText = success ? 'Available' : 'Unavailable';
        const noteHtml = notes ? `<p class="text-xs text-gray-500 mt-1">${notes}</p>` : '';

        statusContainer.innerHTML += `
            <div class="status-item">
                <div>
                    <span class="status-label">${label}</span>
                    ${noteHtml}
                </div>
                <span class="status-badge ${status}">${badgeText}</span>
            </div>
        `;
    };

    // --- WebAuthn Logic ---

    /**
     * Checks the environment for required APIs and features.
     */
    const performInitialChecks = async () => {
        log('Starting environment checks...');

        // 1. Check for Credential Storage API
        let storageApiAvailable = false;
        try {
            const resp = await fetch('/api/credentials');
            storageApiAvailable = resp.ok;
        } catch (e) {
            storageApiAvailable = false;
        }
        renderStatus('Credential Storage API', storageApiAvailable,
            storageApiAvailable
                ? 'KV-backed credential storage is reachable.'
                : 'Could not reach /api/credentials. Ensure the KV binding PASSKEY_KV is configured in the Cloudflare Pages dashboard.');
        if (!storageApiAvailable) {
            log('Credential Storage API is not available. Passkey save/load will not work.', null, 'error');
        }

        // 2. Check for WebAuthn API (PublicKeyCredential)
        const webAuthnAvailable = !!window.PublicKeyCredential;
        renderStatus('WebAuthn API', webAuthnAvailable, 'Checks for <code>window.PublicKeyCredential</code>. If this fails on Android, you may need to call <code>WebSettingsCompat</code> <code>.setWebAuthenticationSupport()</code> in your app.');
        if (!webAuthnAvailable) {
            log('WebAuthn API not found. This browser/WebView does not support WebAuthn.', null, 'error');
        }

        // 3. Check for Conditional Mediation (Passkey Autofill)
        let conditionalMediationAvailable = false;
        if (webAuthnAvailable && PublicKeyCredential.isConditionalMediationAvailable) {
            conditionalMediationAvailable = await PublicKeyCredential.isConditionalMediationAvailable();
        }
        renderStatus('Conditional Mediation', conditionalMediationAvailable, 'Also known as "Passkey Autofill". May not be implemented in WebViews based on Chromium.');
        
        log('Environment checks complete.');
        await loadCredentialsFromStorage();
    };

    /**
     * Loads credentials from local storage and displays them in the options panel.
     */
    const loadCredentialsFromStorage = async () => {
        let creds = [];
        try {
            const resp = await fetch('/api/credentials');
            if (resp.ok) {
                creds = await resp.json();
            } else {
                log('Failed to load credentials from API', { status: resp.status }, 'error');
            }
        } catch (e) {
            log('Network error loading credentials', { message: e.message }, 'error');
        }
        credentialsListDiv.innerHTML = '';

        if (creds.length === 0) {
            credentialsListDiv.innerHTML = '<p class="text-gray-500">No passkeys created yet.</p>';
            return;
        }

        creds.forEach(cred => {
            const el = document.createElement('label');
            el.className = 'credential-item';
            el.innerHTML = `
                <input type="checkbox" class="credential-checkbox" value="${cred.id}">
                <div class="credential-info">
                    <span class="username">${cred.username}</span>
                    <br>
                    ID: ${cred.id.substring(0, 20)}...
                </div>
            `;
            credentialsListDiv.appendChild(el);
        });
    };
    
    /**
     * Saves a credential to local storage.
     * @param {{username: string, id: string, rawId: string, pubKey: string, alg: number}} cred The credential object.
     */
    const saveCredential = async (cred) => {
        const resp = await fetch('/api/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cred),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(`Failed to save credential: ${err.error || resp.status}`);
        }
    };
    
    /**
     * Handles the creation of a new passkey.
     */
    const handleCreateCredential = async () => {
        const username = usernameInput.value;
        if (!username) {
            log('Username cannot be empty.', null, 'error');
            alert('Please enter a username.');
            return;
        }
        log(`Creating passkey for username: ${username}...`);

        try {
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            const rpId = relatedOriginsCheckbox.checked ? RELATED_ORIGIN : window.location.hostname;
            log(`Using RP ID: ${rpId}`);

            const createOptions = {
                challenge,
                rp: { name: 'WebAuthn WebView Demo', id: rpId },
                user: { id: crypto.getRandomValues(new Uint8Array(16)), name: username, displayName: username },
                pubKeyCredParams: [ { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 } ],
                authenticatorSelection: {
                    userVerification: 'required',
                    residentKey: 'required' // 'residentKey' is now an alias for 'discoverableCredential'
                },
                timeout: 60000,
                attestation: 'none'
            };

            const loggableOptions = {
                ...createOptions,
                challenge: bufferToBase64url(createOptions.challenge),
                user: { ...createOptions.user, id: bufferToBase64url(createOptions.user.id) },
            };
            log('Calling navigator.credentials.create() with options:', loggableOptions);

            const credential = await navigator.credentials.create({ publicKey: createOptions });
            log('navigator.credentials.create() successful!', credential, 'success');

            log('--- Verifying new credential (simulated server-side) ---');
            const clientDataJSON = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
            
            const challengeReceived = clientDataJSON.challenge;
            const challengeSent = bufferToBase64url(challenge);
            if (challengeReceived !== challengeSent) {
                throw new Error(`Challenge mismatch! \nExpected: ${challengeSent} \nReceived: ${challengeReceived}`);
            }
            log('✅ Challenge verified');

            validateOrigin(clientDataJSON.origin, window.location.origin, ALLOWED_ANDROID_HASHES);
            log('✅ Origin verified');
            
            if (clientDataJSON.type !== 'webauthn.create') {
                throw new Error(`Type mismatch! \nExpected: 'webauthn.create' \nReceived: '${clientDataJSON.type}'`);
            }
            log('✅ Type verified');
            
            const newCred = {
                username: username,
                id: bufferToBase64url(credential.rawId),
                rawId: bufferToBase64url(credential.rawId),
                pubKey: bufferToBase64url(credential.response.getPublicKey()),
                alg: credential.response.getPublicKeyAlgorithm()
            };
            await saveCredential(newCred);
            log('✅ Credential stored via API.', newCred, 'success');
            usernameInput.value = '';
            await loadCredentialsFromStorage();

        } catch (err) {
            log('Error during credential creation', { name: err.name, message: err.message }, 'error');
        }
    };

    /**
     * Handles the login flow (getAssertion).
     */
    const handleGetAssertion = async () => {
        log('Starting passkey login...');

        try {
            const selectedCreds = Array.from(document.querySelectorAll('.credential-checkbox:checked'))
                .map(cb => ({ type: 'public-key', id: base64urlToBuffer(cb.value) }));
            
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            const rpId = relatedOriginsCheckbox.checked ? RELATED_ORIGIN : window.location.hostname;
            log(`Using RP ID: ${rpId}`);

            const getOptions = {
                challenge,
                timeout: 60000,
                userVerification: 'required',
                rpId: rpId,
            };

            if (selectedCreds.length > 0) {
                getOptions.allowCredentials = selectedCreds;
            }
            
            const loggableOptions = {
                ...getOptions,
                challenge: bufferToBase64url(getOptions.challenge),
                ...(getOptions.allowCredentials && {
                    allowCredentials: getOptions.allowCredentials.map(cred => ({ ...cred, id: bufferToBase64url(cred.id) }))
                })
            };
            log('Calling navigator.credentials.get() with options:', loggableOptions);

            const assertion = await navigator.credentials.get({ publicKey: getOptions });
            log('navigator.credentials.get() successful!', assertion, 'success');

            log('--- Verifying assertion (simulated server-side) ---');

            let allCreds = [];
            try {
                const credsResp = await fetch('/api/credentials');
                if (credsResp.ok) {
                    allCreds = await credsResp.json();
                }
            } catch (e) {
                throw new Error(`Could not load credentials for verification: ${e.message}`);
            }
            const credToVerify = allCreds.find(c => c.id === bufferToBase64url(assertion.rawId));

            if (!credToVerify) {
                throw new Error(`Could not find credential with ID ${bufferToBase64url(assertion.rawId)} in storage.`);
            }
            log('Found matching credential in storage for verification.', credToVerify);

            const clientDataJSON = JSON.parse(new TextDecoder().decode(assertion.response.clientDataJSON));
            
            const challengeReceived = clientDataJSON.challenge;
            const challengeSent = bufferToBase64url(challenge);
            if (challengeReceived !== challengeSent) {
                throw new Error(`Challenge mismatch! \nExpected: ${challengeSent} \nReceived: ${challengeReceived}`);
            }
            log('✅ Challenge verified');

            validateOrigin(clientDataJSON.origin, window.location.origin, ALLOWED_ANDROID_HASHES);
            log('✅ Origin verified');

            const authenticatorData = assertion.response.authenticatorData;
            const clientDataHash = await crypto.subtle.digest('SHA-256', assertion.response.clientDataJSON);
            const signatureBase = new Uint8Array([...new Uint8Array(authenticatorData), ...new Uint8Array(clientDataHash)]);
            
            const publicKey = await crypto.subtle.importKey(
                'spki', 
                base64urlToBuffer(credToVerify.pubKey),
                { name: 'ECDSA', namedCurve: 'P-256' }, 
                true, 
                ['verify']
            );
            
            log('Imported public key for verification.');

            const rawSignature = derToRawSignature(assertion.response.signature);

            const signatureIsValid = await crypto.subtle.verify(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                publicKey,
                rawSignature,
                signatureBase
            );
            
            if (signatureIsValid) {
                log('✅ SIGNATURE VERIFIED!', null, 'success');
                log(`Welcome back, ${credToVerify.username}!`, null, 'success');
            } else {
                throw new Error("Signature verification failed!");
            }

        } catch (err) {
            log('Error during assertion', { name: err.name, message: err.message }, 'error');
        }
    };

    /**
     * Handles the logic for the clear storage button.
     */
    let isConfirmingClear = false;
    let clearConfirmTimeout;

    const resetClearButtonState = () => {
        clearStorageBtn.textContent = 'Clear All Stored Passkeys';
        clearStorageBtn.classList.remove('bg-yellow-500', 'hover:bg-yellow-600', 'focus:ring-yellow-300');
        clearStorageBtn.classList.add('bg-red-600', 'hover:bg-red-700', 'focus:ring-red-300');
        isConfirmingClear = false;
    };

    const handleClearStorage = async () => {
        if (!isConfirmingClear) {
            clearStorageBtn.textContent = 'Are you sure? Click again to clear';
            clearStorageBtn.classList.remove('bg-red-600', 'hover:bg-red-700', 'focus:ring-red-300');
            clearStorageBtn.classList.add('bg-yellow-500', 'hover:bg-yellow-600', 'focus:ring-yellow-300');
            isConfirmingClear = true;

            clearConfirmTimeout = setTimeout(() => {
                resetClearButtonState();
                log('Clear storage action timed out.', '', 'info');
            }, 4000);
        } else {
            clearTimeout(clearConfirmTimeout);
            try {
                const resp = await fetch('/api/credentials', { method: 'DELETE' });
                if (resp.ok || resp.status === 204) {
                    log('All passkeys cleared.', '', 'success');
                } else {
                    log('Failed to clear passkeys from API', { status: resp.status }, 'error');
                }
            } catch (e) {
                log('Network error clearing credentials', { message: e.message }, 'error');
            }
            await loadCredentialsFromStorage();
            resetClearButtonState();
        }
    };

    // --- Event Listeners ---
    createCredentialBtn.addEventListener('click', handleCreateCredential);
    getAssertionBtn.addEventListener('click', handleGetAssertion);
    clearStorageBtn.addEventListener('click', handleClearStorage);

    // --- Initialisation ---
    performInitialChecks();
});
