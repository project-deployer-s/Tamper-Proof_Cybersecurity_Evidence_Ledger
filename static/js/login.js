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

  function showRestorePane() {
    document.querySelector('.tabs').hidden = true;
    panes.signin.hidden = true;
    panes.signup.hidden = true;
    $('pane-restore').hidden = false;
  }

  panes.signin.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('si-error', '');

    const submitButton = panes.signin.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    submitButton.textContent = 'Signing in...';

    try {
      const result = await api.login(
        $('si-user').value.trim(),
        $('si-pass').value
      );

      if (!result.ok) {
        showError('si-error', result.error);
        return;
      }

      const me = api.currentUser();
      if (!me || me.id === undefined || me.id === null) {
        throw new Error('Login succeeded, but the account ID was not returned. Please sign in again.');
      }

      // A storage read error is NOT the same as a missing key.
      // Never send users to key restoration on a transient IndexedDB failure.
      let existingKey;
      try {
        existingKey = await loadPrivateKey(me.id);
      } catch (storageError) {
        console.error('Signing-key storage check failed:', storageError);
        showError(
          'si-error',
          'You are signed in, but browser key storage could not be checked. Do not generate a new key. Refresh the page and try again. If this continues, close other project tabs and check browser site-storage permissions.'
        );
        return;
      }

      if (!existingKey) {
        showRestorePane();
        return;
      }

      location.href = 'inbox.html';
    } catch (error) {
      console.error('Login/key check error:', error);
      showError('si-error', error.message || 'Unable to complete login.');
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = 'Sign in';
    }
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

      const me = api.currentUser();
      if (!me?.id) throw new Error('Account ID is missing. Please sign in again.');

      // Store locally first so a temporary server issue does not lose the only local copy.
      await savePrivateKey(me.id, keyPair.privateKey);

      const result = await api.registerPublicKey(publicKeyBase64);
      if (!result.ok) {
        // Do not silently generate another key. The local key remains available.
        throw new Error(result.error || 'Public-key registration failed. Your private key remains saved locally.');
      }

      const hash = await crypto.subtle.digest('SHA-256', publicKeyBuffer);
      const fingerprint = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(':')
        .toUpperCase();

      $('fingerprint').textContent = fingerprint;
      $('key-result').hidden = false;
      button.textContent = 'Key created successfully';
    } catch (error) {
      console.error('Key creation error:', error);
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

  $('restore-key').addEventListener('click', async () => {
    const button = $('restore-key');
    const fileInput = $('key-backup-file');

    showError('restore-error', '');
    $('restore-success').hidden = true;

    const file = fileInput.files[0];
    if (!file) {
      showError('restore-error', 'Select your private-key backup file first.');
      return;
    }

    const me = api.currentUser();
    if (!me?.id) {
      showError('restore-error', 'Your login session is missing. Please sign in again.');
      return;
    }

    button.disabled = true;
    button.textContent = 'Verifying backup...';

    try {
      const backup = (await file.text()).trim();
      if (!backup || backup.length > 10000) {
        throw new Error('The backup file is empty or invalid.');
      }

      const privateKey = await importPrivateKey(backup);
      const result = await api.getUserKeys();

      if (!result.ok) {
        throw new Error(result.error || 'Unable to retrieve registered public keys. Please retry.');
      }

      const activeKeys = (result.data.keys || []).filter(
        key => !key.is_revoked &&
          key.algorithm === 'ECDSA-P256' &&
          key.public_key
      );

      if (!activeKeys.length) {
        throw new Error('No active ECDSA-P256 public key was found for this account.');
      }

      let matchedKey = null;
      for (const key of activeKeys) {
        try {
          if (await matchesPublicKey(privateKey, key.public_key)) {
            matchedKey = key;
            break;
          }
        } catch (verificationError) {
          console.warn('Could not test public key:', key.id, verificationError);
        }
      }

      if (!matchedKey) {
        throw new Error('This backup does not match any active public key on your account. No key was changed.');
      }

      await savePrivateKey(me.id, privateKey);

      // Read back from IndexedDB to confirm persistence before reporting success.
      const savedKey = await loadPrivateKey(me.id);
      if (!savedKey || !(await matchesPublicKey(savedKey, matchedKey.public_key))) {
        throw new Error('The key was verified but could not be confirmed after saving. Keep your backup and retry.');
      }

      $('restore-success').textContent =
        `Existing private key restored and verified (Key ID ${matchedKey.id}).`;
      $('restore-success').hidden = false;
      fileInput.value = '';
      button.textContent = 'Key restored';
      App.toast('Existing signing key restored successfully.');
    } catch (error) {
      console.error('Private-key restoration failed:', error);
      showError('restore-error', error.message || 'Private-key restoration failed. Your existing stored key was not intentionally deleted.');
      button.textContent = 'Restore existing key';
      button.disabled = false;
    }
  });
})();
