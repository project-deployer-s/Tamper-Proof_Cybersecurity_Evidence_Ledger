
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const tabs = {
    signin: $('tab-signin'),
    signup: $('tab-signup')
  };

  const panes = {
    signin: $('pane-signin'),
    signup: $('pane-signup')
  };

  function showTab(name) {
    Object.keys(tabs).forEach((key) => {
      const active = key === name;
      tabs[key].setAttribute('aria-selected', active ? 'true' : 'false');
      panes[key].hidden = !active;
    });
  }

  tabs.signin.addEventListener('click', () => showTab('signin'));
  tabs.signup.addEventListener('click', () => showTab('signup'));

  function showError(id, message) {
    const el = $(id);
    el.textContent = message;
    el.hidden = !message;
  }

  panes.signin.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('si-error', '');

    const result = await api.login(
      $('si-user').value,
      $('si-pass').value
    );

    if (!result.ok) {
      return showError('si-error', result.error);
    }

    const me = api.currentUser();

try {
  const existingKey = await loadPrivateKey(me.id);

  if (!existingKey) {
    document.querySelector('.tabs').hidden = true;
    panes.signin.hidden = true;
    panes.signup.hidden = true;
    $('pane-restore').hidden = false;
    return;
  }
} catch (error) {
  showError('si-error', 'Unable to check browser key storage.');
  return;
}

location.href = 'inbox.html';
  });

  panes.signup.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('su-error', '');

    const result = await api.register(
      $('su-user').value,
      $('su-email').value,
      $('su-pass').value
    );

    if (!result.ok) {
      return showError('su-error', result.error);
    }

    document.querySelector('.tabs').hidden = true;
    panes.signin.hidden = true;
    panes.signup.hidden = true;
    $('pane-key').hidden = false;
    $('make-key').focus();
  });

  let backupText = '';

  $('make-key').addEventListener('click', async (e) => {
    const button = e.currentTarget;

    button.disabled = true;
    button.textContent = 'Creating key...';
    showError('su-error', '');

    try {
      const keyPair = await generateKeyPair();

      const publicKeyBuffer = await exportPublicKey(keyPair.publicKey);
      const privateKeyBuffer = await exportPrivateKey(keyPair.privateKey);

      const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);
      backupText = arrayBufferToBase64(privateKeyBuffer);

      const result = await api.registerPublicKey(publicKeyBase64);

      if (!result.ok) {
        throw new Error(result.error);
      }

      const me = api.currentUser();
      await savePrivateKey(me.id, keyPair.privateKey);

      const hash = await crypto.subtle.digest(
        'SHA-256',
        publicKeyBuffer
      );

      const fingerprint = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(':')
        .toUpperCase();

      $('fingerprint').textContent = fingerprint;
      $('key-result').hidden = false;

      button.textContent = 'Key created successfully';

    } catch (error) {
      showError('su-error', error.message || 'Key generation failed.');
      button.disabled = false;
      button.textContent = 'Try again';
    }
  });

  $('download-key').addEventListener('click', () => {
    if (!backupText) {
      App.toast('No private key backup available.');
      return;
    }

    downloadPrivateKey(backupText);
    App.toast('Private key backup downloaded.');
  });

  // Restore an existing private key without registering a new public key.
  $('restore-key').addEventListener('click', async () => {
    const button = $('restore-key');
    const fileInput = $('key-backup-file');

    showError('restore-error', '');

    const file = fileInput.files[0];

    if (!file) {
      return showError('restore-error', 'Select your private-key backup file first.');
    }

    const me = api.currentUser();

    if (!me) {
      return showError('restore-error', 'Please sign in again.');
    }

    button.disabled = true;
    button.textContent = 'Verifying backup...';

    try {
      const backup = (await file.text()).trim();

      if (!backup || backup.length > 10000) {
        throw new Error('The backup file is empty or invalid.');
      }

      // Import locally. The private key is never sent to the server.
      const privateKey = await importPrivateKey(backup);

      // Fetch only this account's public keys.
      const result = await api.getUserKeys();

      if (!result.ok) {
        throw new Error(result.error || 'Unable to retrieve your public keys.');
      }

      const activeKeys = (result.data.keys || []).filter(
        key =>
          !key.is_revoked &&
          key.algorithm === 'ECDSA-P256' &&
          key.public_key
      );

      if (activeKeys.length === 0) {
        throw new Error('No active ECDSA-P256 public key was found.');
      }

      let matchedKey = null;

      for (const key of activeKeys) {
        try {
          if (await matchesPublicKey(privateKey, key.public_key)) {
            matchedKey = key;
            break;
          }
        } catch (error) {
          // An incompatible public key is skipped; other keys are checked.
        }
      }

      if (!matchedKey) {
        throw new Error(
          'This backup does not match any active public key on your account. Nothing was saved.'
        );
      }

      // Save only after successful cryptographic verification.
      await savePrivateKey(me.id, privateKey);

      $('restore-success').textContent =
        `Existing private key restored successfully (Key ID ${matchedKey.id}).`;

      $('restore-success').hidden = false;
      fileInput.value = '';

      button.textContent = 'Key restored';

      App.toast('Existing signing key restored successfully.');

    } catch (error) {
      showError(
        'restore-error',
        error.message || 'Unable to restore the private key.'
      );

      button.textContent = 'Restore existing key';
      button.disabled = false;
    }
  });

})();
