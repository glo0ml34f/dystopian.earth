(function () {
    const form = document.getElementById('join-form');
    if (!form) {
        return;
    }

    const handleInput = document.getElementById('handle');
    const emailInput = document.getElementById('email');
    const inviteInput = document.getElementById('invite-code');
    const flagInput = document.getElementById('flag-input');
    const flagButton = document.getElementById('flag-submit');
    const flagError = document.getElementById('flag-error');
    const flagSuccess = document.getElementById('flag-success');
    const container = form.closest('section[data-token-ttl]');
    const ttlSeconds = container ? parseInt(container.dataset.tokenTtl || '0', 10) : 0;

    function resetMessages() {
        if (flagError) {
            flagError.hidden = true;
            flagError.textContent = '';
        }
        if (flagSuccess) {
            flagSuccess.hidden = true;
            flagSuccess.textContent = '';
        }
    }

    async function verifyFlag() {
        if (!flagInput || !flagButton) {
            return;
        }

        const flag = flagInput.value.trim();
        const handle = handleInput ? handleInput.value.trim() : '';
        const email = emailInput ? emailInput.value.trim() : '';

        resetMessages();

        if (!handle || !email) {
            if (flagError) {
                flagError.textContent = 'Add your handle and email before minting an invite token.';
                flagError.hidden = false;
            }
            return;
        }

        if (!flag) {
            if (flagError) {
                flagError.textContent = 'Enter a flag from today\'s challenge to mint an invite token.';
                flagError.hidden = false;
            }
            return;
        }

        flagButton.disabled = true;
        const originalLabel = flagButton.textContent;
        flagButton.textContent = 'Verifying…';

        try {
            const response = await fetch('/join/flag', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                body: JSON.stringify({ flag, handle, email }),
            });

            if (!response.ok) {
                const message = (await response.text()).trim() || 'Flag rejected.';
                throw new Error(message);
            }

            let payload = {};
            try {
                payload = await response.json();
            } catch (err) {
                throw new Error('Server returned an unexpected response.');
            }

            if (inviteInput && payload.invite_code) {
                inviteInput.value = payload.invite_code;
                inviteInput.focus();
                inviteInput.select();
            }

            if (flagInput) {
                flagInput.value = '';
            }

            if (flagSuccess) {
                let message = 'Flag verified. Invite token inserted above.';
                if (payload.expires_at) {
                    const expires = new Date(payload.expires_at);
                    if (!Number.isNaN(expires.getTime())) {
                        const now = new Date();
                        const diffMs = expires.getTime() - now.getTime();
                        const minutes = Math.max(1, Math.round(diffMs / 60000));
                        const timeString = expires.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                        message += ` Expires in about ${minutes} minute${minutes === 1 ? '' : 's'} (around ${timeString}).`;
                    }
                } else if (ttlSeconds > 0) {
                    const minutes = Math.max(1, Math.round(ttlSeconds / 60));
                    message += ` Expires in about ${minutes} minute${minutes === 1 ? '' : 's'}.`;
                }
                flagSuccess.textContent = message;
                flagSuccess.hidden = false;
            }
        } catch (error) {
            if (flagError) {
                flagError.textContent = error instanceof Error ? error.message : 'Flag verification failed.';
                flagError.hidden = false;
            }
        } finally {
            flagButton.disabled = false;
            flagButton.textContent = originalLabel;
        }
    }

    if (flagButton) {
        flagButton.addEventListener('click', verifyFlag);
    }
})();
