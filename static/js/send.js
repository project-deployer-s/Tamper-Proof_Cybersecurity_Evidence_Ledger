
(async function () {
  'use strict';

  if (!App.requireLogin()) return;

  App.mountNav('send');

  const me = api.currentUser();
  const $ = (id) => document.getElementById(id);

  const form = $('send-form');
  const button = $('send-btn');

  function showError(message) {
    $('send-error').textContent = message;
    $('send-error').hidden = !message;
  }

  function toBase64(bytes) {
    let binary = '';

    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }

    return btoa(binary);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  // Load real users.
  const userResult = await api.listUsers();

  if (!userResult.ok) {
    showError(userResult.error);
    return;
  }

  const users = userResult.users;

  $('to').innerHTML = users.map(user =>
    `<option value="${App.esc(user.username)}">${App.esc(user.username)}</option>`
  ).join('');

  // Update character count.
  $('body').addEventListener('input', () => {
    $('count').textContent = $('body').value.length;
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    showError('');
    $('outcome').innerHTML = '';

    const receiver = $('to').value;
    const message = $('body').value.trim();

    if (!receiver || !message) {
      showError('Select a receiver and enter a message.');
      return;
    }

    button.disabled = true;
    button.textContent = 'Signing message...';

    try {
      // 1. Retrieve active public key.
      const keysResult = await api.getUserKeys();

      if (!keysResult.ok) {
        throw new Error(keysResult.error);
      }

      const activeKey = keysResult.data.keys.find(
        key => !key.is_revoked
      );

      if (!activeKey) {
        throw new Error('No active signing key found. Create a new key first.');
      }

      // 2. Retrieve private key from IndexedDB.
      const privateKey = await loadPrivateKey(me.id);

      if (!privateKey) {
        throw new Error(
          'Private key not found in this browser. You must restore or create your signing key.'
        );
      }

      // 3. Generate timestamp and unique nonce.
      const timestamp = new Date().toISOString();

      const nonceBytes = crypto.getRandomValues(
        new Uint8Array(32)
      );

      const nonce = bytesToHex(nonceBytes);

      // 4. Create canonical payload.
      const payloadObject = {
        sender: me.username,
        receiver: receiver,
        timestamp: timestamp,
        nonce: nonce,
        message: message
      };

      const canonicalPayload = JSON.stringify(payloadObject);

      const encoder = new TextEncoder();
      const payloadBytes = encoder.encode(canonicalPayload);

      // 5. Calculate SHA-256 content hash.
      const hashBuffer = await crypto.subtle.digest(
        'SHA-256',
        payloadBytes
      );

      const contentHash = bytesToHex(
        new Uint8Array(hashBuffer)
      );

      // 6. Sign canonical payload with ECDSA P-256.
      const signatureBuffer = await crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: 'SHA-256'
        },
        privateKey,
        payloadBytes
      );

      const signature = toBase64(
        new Uint8Array(signatureBuffer)
      );

      // 7. Submit signed message to Flask.
      button.textContent = 'Sending message...';

      const result = await api.sendMessage({
        public_key_id: activeKey.id,
        sender: me.username,
        receiver: receiver,
        timestamp: timestamp,
        nonce: nonce,
        message: message,
        content_hash: contentHash,
        signature: signature
      });

      if (!result.ok) {
        throw new Error(result.error);
      }

      const sent = result.data.data;

      // 8. Display success.
      $('outcome').innerHTML = `
        <div class="seal ok" role="status">
          <span class="seal-icon" aria-hidden="true">✓</span>
          <div>
            <div class="seal-title">
              Sent to ${App.esc(sent.receiver)}
            </div>
            <p>
              Signed and recorded in ledger entry
              #${result.data.ledger_seq}.
            </p>
          </div>
        </div>

        <div class="panel" style="margin-top:16px">
          <h2 style="margin-bottom:10px">What was signed</h2>

          <dl class="facts">
            <dt>From</dt>
            <dd>${App.esc(sent.sender)}</dd>

            <dt>To</dt>
            <dd>${App.esc(sent.receiver)}</dd>

            <dt>Time</dt>
            <dd>${App.esc(timestamp)}</dd>

            <dt>Nonce</dt>
            <dd class="mono">${App.esc(nonce)}</dd>

            <dt>Content hash</dt>
            <dd class="mono">${App.esc(contentHash)}</dd>
          </dl>

          <p class="fine">
            Your message was signed using ECDSA P-256.
          </p>

          <a class="btn secondary" href="ledger.html">
            See it in the ledger
          </a>
        </div>
      `;

      form.reset();
      $('count').textContent = '0';

    } catch (error) {
      showError(error.message || 'Message submission failed.');
    } finally {
      button.disabled = false;
      button.textContent = 'Sign and send';
    }
  });
})();
