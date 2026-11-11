
(async function () {
  'use strict';

  if (!App.requireLogin()) return;

  App.mountNav('send');

  const me = api.currentUser();
  const $ = (id) => document.getElementById(id);

  const form = $('send-form');
  const button = $('send-btn');
  const fileInput = $('attachments');

  const expiryModeInput = $('expiry-mode');
  const expiryDurationInput = $('expiry-duration');
  const expiryUnitInput = $('expiry-unit');
  const expiryDurationFields = $('expiry-duration-fields');

  const MIN_EXPIRY_SECONDS = 60;
  const MAX_EXPIRY_SECONDS = 365 * 24 * 60 * 60;
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
        throw new Error(`File type not allowed: ${file.name}`);
      }

      if (file.size === 0) {
        throw new Error(`${file.name} is empty.`);
      }

      if (file.size > MAX_FILE_SIZE) {
        throw new Error(`${file.name} exceeds the 10 MB limit.`);
      }
    }
  }

  function getExpiryLabel(seconds) {
    if (seconds === null) return 'Never expires';

    if (seconds % 86400 === 0) {
      const days = seconds / 86400;
      return `${days} day${days === 1 ? '' : 's'}`;
    }

    if (seconds % 3600 === 0) {
      const hours = seconds / 3600;
      return `${hours} hour${hours === 1 ? '' : 's'}`;
    }

    const minutes = seconds / 60;
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  }

  function updateExpiryControls() {
    const neverExpires = expiryModeInput.value === 'never';

    expiryDurationFields.hidden = neverExpires;
    expiryDurationInput.required = !neverExpires;
    expiryDurationInput.disabled = neverExpires;
    expiryUnitInput.disabled = neverExpires;

    const unitSeconds = Number(expiryUnitInput.value);

    if ([60, 3600, 86400].includes(unitSeconds)) {
      expiryDurationInput.max = String(
        Math.floor(MAX_EXPIRY_SECONDS / unitSeconds)
      );
    }
  }

  function getExpirySeconds() {
    if (expiryModeInput.value === 'never') {
      return null;
    }

    const rawDuration = expiryDurationInput.value.trim();

    if (!/^\d+$/.test(rawDuration)) {
      throw new Error(
        'Enter a whole-number expiry duration.'
      );
    }

    const duration = Number(rawDuration);

    // IMPORTANT:
    // These values match the option values in send.html.
    const unitSeconds = Number(expiryUnitInput.value);

    const allowedUnits = [60, 3600, 86400];

    if (!allowedUnits.includes(unitSeconds)) {
      throw new Error('Select a valid expiry time unit.');
    }

    const seconds = duration * unitSeconds;

    if (
      !Number.isSafeInteger(duration) ||
      duration < 1 ||
      !Number.isSafeInteger(seconds) ||
      seconds < MIN_EXPIRY_SECONDS ||
      seconds > MAX_EXPIRY_SECONDS
    ) {
      throw new Error(
        'Expiry must be between 1 minute and 365 days.'
      );
    }

    return seconds;
  }

  // Load users.
  const userResult = await api.listUsers();

  if (!userResult.ok) {
    showError(userResult.error);
    return;
  }

  $('to').innerHTML = userResult.users.map(user =>
    `<option value="${App.esc(user.username)}">${App.esc(user.username)}</option>`
  ).join('');

  // Character counter.
  $('body').addEventListener('input', () => {
    $('count').textContent = $('body').value.length;
  });

  // Attachment handling.
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

  // Expiry controls.
  expiryModeInput.addEventListener(
    'change',
    updateExpiryControls
  );

  expiryUnitInput.addEventListener(
    'change',
    updateExpiryControls
  );

  updateExpiryControls();

  // Submit message.
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

    let expirySeconds;

    try {
      expirySeconds = getExpirySeconds();
      validateFiles(files);
    } catch (error) {
      showError(error.message);
      return;
    }

    button.disabled = true;
    button.textContent = 'Signing message...';

    try {
      // 1. Get active public key.
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

      // 2. Load private key.
      const privateKey = await loadPrivateKey(me.id);

      if (!privateKey) {
        throw new Error(
          'Private key not found in this browser. Restore or create your signing key.'
        );
      }

      // 3. Timestamp and nonce.
      const timestamp = new Date().toISOString();

      const nonceBytes = crypto.getRandomValues(
        new Uint8Array(32)
      );

      const nonce = bytesToHex(nonceBytes);

      // 4. Hash attachments.
      button.textContent = 'Hashing attachments...';

      const attachmentHashes = await Promise.all(
        files.map(file => calculateFileHash(file))
      );

      attachmentHashes.sort();

      // 5. Build canonical payload.
      const payloadObject = {
        sender: me.username,
        receiver: receiver,
        timestamp: timestamp,
        nonce: nonce,
        message: message
      };

      if (attachmentHashes.length > 0) {
        payloadObject.attachment_hashes = attachmentHashes;
      }

      if (expirySeconds !== null) {
        payloadObject.expiry_seconds = expirySeconds;
      }

      const canonicalPayload = JSON.stringify(payloadObject);

      const payloadBytes = new TextEncoder().encode(
        canonicalPayload
      );

      // 6. Calculate content hash.
      const hashBuffer = await crypto.subtle.digest(
        'SHA-256',
        payloadBytes
      );

      const contentHash = bytesToHex(
        new Uint8Array(hashBuffer)
      );

      // 7. Sign payload.
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

      // 8. Prepare request.
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

      formData.append(
        'expiry_seconds',
        expirySeconds === null ? '' : String(expirySeconds)
      );

      files.forEach(file => {
        formData.append('attachments', file);
      });

      // 9. Send message.
      button.textContent = 'Uploading and sending...';

      const result = await api.sendMessage(formData);

      if (!result.ok) {
        throw new Error(result.error);
      }

      const sent = result.data.data;

      // 10. Display result.
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

            <dt>Availability</dt>
            <dd>${App.esc(getExpiryLabel(expirySeconds))}</dd>

            <dt>Nonce</dt>
            <dd class="mono">${App.esc(nonce)}</dd>

            <dt>Content hash</dt>
            <dd class="mono">${App.esc(contentHash)}</dd>

            <dt>Attachments</dt>
            <dd>${files.length}</dd>
          </dl>

          <p class="fine">
            Your message, attachment hashes, and expiry duration
            were signed using ECDSA P-256.
          </p>

          <a class="btn secondary" href="ledger.html">
            See it in the ledger
          </a>
        </div>
      `;

      form.reset();

      updateExpiryControls();

      $('count').textContent = '0';
      $('attachment-list').innerHTML = '';

    } catch (error) {
      showError(
        error.message || 'Message submission failed.'
      );
    } finally {
      button.disabled = false;
      button.textContent = 'Sign and send';
    }
  });
})();
