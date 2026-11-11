
(async function () {
  'use strict';

  if (!App.requireLogin()) return;

  App.mountNav('send');

  const me = api.currentUser();
  const $ = (id) => document.getElementById(id);

  const form = $('send-form');
  const button = $('send-btn');
  const fileInput = $('attachments');

  const MAX_FILE_SIZE = 10 * 1024 * 1024;

  const ALLOWED_EXTENSIONS = [
    'pdf', 'txt', 'csv', 'png',
    'jpg', 'jpeg', 'docx'
  ];

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

  async function calculateFileHash(file) {
    const buffer = await file.arrayBuffer();

    const hashBuffer = await crypto.subtle.digest(
      'SHA-256',
      buffer
    );

    return bytesToHex(new Uint8Array(hashBuffer));
  }

  function validateFiles(files) {
    for (const file of files) {
      const extension = file.name.includes('.')
        ? file.name.split('.').pop().toLowerCase()
        : '';

      if (!ALLOWED_EXTENSIONS.includes(extension)) {
        throw new Error(
          `File type not allowed: ${file.name}`
        );
      }

      if (file.size === 0) {
        throw new Error(
          `${file.name} is empty.`
        );
      }

      if (file.size > MAX_FILE_SIZE) {
        throw new Error(
          `${file.name} exceeds the 10 MB limit.`
        );
      }
    }
  }

  // Load real users.
  const userResult = await api.listUsers();

  if (!userResult.ok) {
    showError(userResult.error);
    return;
  }

  $('to').innerHTML = userResult.users.map(user =>
    `<option value="${App.esc(user.username)}">${App.esc(user.username)}</option>`
  ).join('');

  // Update character count.
  $('body').addEventListener('input', () => {
    $('count').textContent = $('body').value.length;
  });

  // Display selected attachments.
  fileInput.addEventListener('change', () => {
    showError('');

    const files = Array.from(fileInput.files);
    const list = $('attachment-list');

    list.innerHTML = '';

    try {
      validateFiles(files);

      files.forEach(file => {
        const item = document.createElement('p');

        item.className = 'hint';
        item.textContent =
          `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;

        list.appendChild(item);
      });

    } catch (error) {
      fileInput.value = '';
      list.innerHTML = '';
      showError(error.message);
    }
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    showError('');
    $('outcome').innerHTML = '';

    const receiver = $('to').value;
    const message = $('body').value.trim();
    const files = Array.from(fileInput.files);

    if (!receiver || !message) {
      showError('Select a receiver and enter a message.');
      return;
    }

    try {
      validateFiles(files);
    } catch (error) {
      showError(error.message);
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
        throw new Error(
          'No active signing key found. Create a new key first.'
        );
      }

      // 2. Retrieve private key from IndexedDB.
      const privateKey = await loadPrivateKey(me.id);

      if (!privateKey) {
        throw new Error(
          'Private key not found in this browser. Restore or create your signing key.'
        );
      }

      // 3. Generate timestamp and unique nonce.
      const timestamp = new Date().toISOString();

      const nonceBytes = crypto.getRandomValues(
        new Uint8Array(32)
      );

      const nonce = bytesToHex(nonceBytes);

      // 4. Calculate SHA-256 hashes of attachments.
      button.textContent = 'Hashing attachments...';

      const attachmentHashes = await Promise.all(
        files.map(file => calculateFileHash(file))
      );

      // Sort hashes to ensure consistent canonical payload.
      attachmentHashes.sort();

      // 5. Create canonical payload.
      const payloadObject = {
        sender: me.username,
        receiver: receiver,
        timestamp: timestamp,
        nonce: nonce,
        message: message
      };

      // Preserve the old format when no files are attached.
      if (attachmentHashes.length > 0) {
        payloadObject.attachment_hashes = attachmentHashes;
      }

      const canonicalPayload = JSON.stringify(payloadObject);

      const encoder = new TextEncoder();
      const payloadBytes = encoder.encode(canonicalPayload);

      // 6. Calculate SHA-256 content hash.
      const hashBuffer = await crypto.subtle.digest(
        'SHA-256',
        payloadBytes
      );

      const contentHash = bytesToHex(
        new Uint8Array(hashBuffer)
      );

      // 7. Sign canonical payload with ECDSA P-256.
      button.textContent = 'Signing message...';

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

      // 8. Prepare multipart request.
      const formData = new FormData();

      formData.append('public_key_id', activeKey.id);
      formData.append('sender', me.username);
      formData.append('receiver', receiver);
      formData.append('timestamp', timestamp);
      formData.append('nonce', nonce);
      formData.append('message', message);
      formData.append('content_hash', contentHash);
      formData.append('signature', signature);

      formData.append(
        'attachment_hashes',
        JSON.stringify(attachmentHashes)
      );

      files.forEach(file => {
        formData.append('attachments', file);
      });

      // 9. Submit signed message and attachments.
      button.textContent = 'Uploading and sending...';

      const result = await api.sendMessage(formData);

      if (!result.ok) {
        throw new Error(result.error);
      }

      const sent = result.data.data;

      // 10. Display success.
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

            <dt>Attachments</dt>
            <dd>${files.length}</dd>
          </dl>

          <p class="fine">
            Your message and attachment hashes were signed using ECDSA P-256.
          </p>

          <a class="btn secondary" href="ledger.html">
            See it in the ledger
          </a>
        </div>
      `;

      form.reset();
      $('count').textContent = '0';
      $('attachment-list').innerHTML = '';

    } catch (error) {
      showError(error.message || 'Message submission failed.');
    } finally {
      button.disabled = false;
      button.textContent = 'Sign and send';
    }
  });
})();
