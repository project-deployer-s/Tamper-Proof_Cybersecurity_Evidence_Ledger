(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const tabs = { signin: $('tab-signin'), signup: $('tab-signup') };
  const panes = { signin: $('pane-signin'), signup: $('pane-signup') };
  let pendingPrivateKey = null;
  let pendingPublicKey = null;
  let pendingPublicKeyId = null;
  let pendingCloudBackup = null;

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

  function showExclusivePane(id) {
    document.querySelector('.tabs').hidden = true;
    panes.signin.hidden = true;
    panes.signup.hidden = true;
    $('pane-key').hidden = id !== 'pane-key';
    $('pane-restore').hidden = id !== 'pane-restore';
  }

  function showSignInAfterRecovery() {
    // Re-authenticate to obtain a fresh JWT before opening the inbox.
    document.querySelector('.tabs').hidden = false;
    panes.signin.hidden = false;
    panes.signup.hidden = true;
    $('pane-key').hidden = true;
    $('pane-restore').hidden = true;
    tabs.signin.setAttribute('aria-selected', 'true');
    tabs.signup.setAttribute('aria-selected', 'false');
    $('si-pass').value = '';
    showError('si-error', 'Signing key restored. Please sign in again to continue to your inbox.');
    $('si-user').focus();
  }

  async function activeKeysForCurrentUser() {
    const result = await api.getUserKeys();
    if (!result.ok) throw new Error(result.error || 'Unable to retrieve registered public keys.');
    return (result.data.keys || []).filter(key =>
      !key.is_revoked && key.algorithm === 'ECDSA-P256' && key.public_key
    );
  }

  async function matchPrivateKey(privateKey, keys) {
    for (const key of keys) {
      try {
        if (await matchesPublicKey(privateKey, key.public_key)) return key;
      } catch (error) {
        console.warn('Could not verify registered key:', key.id, error);
      }
    }
    return null;
  }

  async function locateCloudBackup(keys) {
    for (const key of keys) {
      const result = await api.getEncryptedKeyBackup(key.id);
      if (result.ok && result.data.backup) {
        return { key, backup: result.data.backup };
      }
      if (result.status !== 404) {
        console.warn('Cloud backup lookup failed for key', key.id, result.error);
      }
    }
    return null;
  }

  function prepareBackupSetup(privateKey, publicKey, keyId) {
    pendingPrivateKey = privateKey;
    pendingPublicKey = publicKey;
    pendingPublicKeyId = keyId;
    $('recovery-setup').hidden = false;
    $('key-result').hidden = false;
    $('recovery-setup-password').value = '';
    $('recovery-setup-confirm').value = '';
    showExclusivePane('pane-key');
  }

  panes.signin.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('si-error', '');
    const button = panes.signin.querySelector('button[type="submit"]');
    button.disabled = true;
    button.textContent = 'Signing in...';
    try {
      const result = await api.login($('si-user').value.trim(), $('si-pass').value);
      if (!result.ok) { showError('si-error', result.error); return; }
      const me = api.currentUser();
      if (!me || me.id == null) throw new Error('Login succeeded, but the account ID was not returned.');

      let localKey;
      try { localKey = await loadPrivateKey(me.id); }
      catch (storageError) {
        console.error('Signing-key storage check failed:', storageError);
        throw new Error('Browser key storage could not be checked. Do not create a new key. Refresh and retry.');
      }

      const keys = await activeKeysForCurrentUser();
      if (localKey) {
        const matched = await matchPrivateKey(localKey, keys);
        if (!matched) throw new Error('A local signing key exists, but it does not match an active registered public key. No key was replaced.');
        const cloud = await api.getEncryptedKeyBackup(matched.id);
        if (cloud.ok) {
          location.href = 'inbox.html';
          return;
        }
        if (cloud.status === 404) {
          prepareBackupSetup(localKey, matched.public_key, matched.id);
          $('key-setup-title').textContent = 'Protect your existing signing key';
          $('key-setup-description').textContent = 'Your local key is valid, but no encrypted cloud backup exists yet. Create a separate recovery password to protect it.';
          return;
        }
        throw new Error(cloud.error || 'Could not check your encrypted cloud backup. Please retry.');
      }

      const cloud = await locateCloudBackup(keys);
      if (cloud) {
        pendingCloudBackup = cloud.backup;
        pendingPublicKey = cloud.key.public_key;
        pendingPublicKeyId = cloud.key.id;
        $('restore-cloud-info').textContent = `Encrypted backup found for registered key ID ${cloud.key.id}. Enter your separate recovery password to restore it.`;
        $('restore-cloud-password').value = '';
        $('restore-cloud').hidden = false;
        $('restore-cloud-key').hidden = false;
        $('restore-cloud-password').closest('.field').hidden = false;
        showError('restore-error', '');
        $('restore-success').hidden = true;
        $('continue-after-restore').hidden = true;
        showExclusivePane('pane-restore');
        return;
      }

      $('restore-cloud').hidden = false;
      $('restore-cloud-key').hidden = true;
      $('restore-cloud-password').closest('.field').hidden = true;
      $('restore-cloud-info').textContent = 'No encrypted cloud backup was found for this account. If the original private key is not available in this browser, it cannot be recovered from the account password.';
      showExclusivePane('pane-restore');
    } catch (error) {
      console.error('Login/key recovery error:', error);
      showError('si-error', error.message || 'Unable to complete login.');
    } finally {
      button.disabled = false;
      button.textContent = 'Sign in';
    }
  });

  panes.signup.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('su-error', '');
    const result = await api.register($('su-user').value, $('su-email').value, $('su-pass').value);
    if (!result.ok) return showError('su-error', result.error);
    $('key-setup-title').textContent = 'Create your signing key';
    $('key-setup-description').textContent = 'Your private key stays in this browser. A separate recovery password protects an encrypted cloud backup; the password and plaintext key are never sent to the server.';
    $('recovery-setup').hidden = true;
    $('key-result').hidden = true;
    $('make-key').disabled = false;
    $('make-key').textContent = 'Create my key pair';
    showExclusivePane('pane-key');
  });

  $('make-key').addEventListener('click', async (e) => {
    const button = e.currentTarget;
    button.disabled = true;
    button.textContent = 'Creating key...';
    showError('su-error', '');
    try {
      const pair = await generateKeyPair();
      const publicBuffer = await exportPublicKey(pair.publicKey);
      const publicBase64 = arrayBufferToBase64(publicBuffer);
      const me = api.currentUser();
      if (!me?.id) throw new Error('Account ID is missing. Please sign in again.');
      await savePrivateKey(me.id, await lockPrivateKeyForLocalStorage(pair.privateKey));
      const registered = await api.registerPublicKey(publicBase64);
      if (!registered.ok) throw new Error(registered.error || 'Public-key registration failed. Your local key remains saved.');
      const keyId = registered.data?.key?.id;
      if (!keyId) throw new Error('The server did not return the registered public-key ID.');
      pendingPrivateKey = pair.privateKey;
      pendingPublicKey = publicBase64;
      pendingPublicKeyId = keyId;
      $('fingerprint').textContent = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', publicBuffer)))
        .map(byte => byte.toString(16).padStart(2, '0')).join(':').toUpperCase();
      $('key-result').hidden = false;
      $('recovery-setup').hidden = false;
      button.textContent = 'Key created successfully';
    } catch (error) {
      console.error('Key creation error:', error);
      showError('su-error', error.message || 'Key generation failed.');
      button.disabled = false;
      button.textContent = 'Try again';
    }
  });

  $('save-cloud-backup').addEventListener('click', async () => {
    const button = $('save-cloud-backup');
    showError('recovery-setup-error', '');
    const password = $('recovery-setup-password').value;
    const confirm = $('recovery-setup-confirm').value;
    if (password.length < 12) return showError('recovery-setup-error', 'Use a recovery password with at least 12 characters.');
    if (password !== confirm) return showError('recovery-setup-error', 'The recovery passwords do not match.');
    if (!pendingPrivateKey || !pendingPublicKeyId) return showError('recovery-setup-error', 'Signing-key setup context is missing. Sign in again.');
    button.disabled = true;
    button.textContent = 'Encrypting and saving...';
    try {
      const me = api.currentUser();
      const backup = await createEncryptedKeyBackup(pendingPrivateKey, password, me.id, pendingPublicKeyId);
      const saved = await api.saveEncryptedKeyBackup(pendingPublicKeyId, backup);
      if (!saved.ok) throw new Error(saved.error || 'Could not save encrypted cloud backup.');
      downloadEncryptedKeyBackup(backup);
      await savePrivateKey(me.id, await lockPrivateKeyForLocalStorage(pendingPrivateKey));
      $('recovery-setup-success').textContent = 'Encrypted cloud backup saved. An additional encrypted backup file has been downloaded. Store it separately from your recovery password.';
      $('recovery-setup-success').hidden = false;
      $('recovery-setup-password').value = '';
      $('recovery-setup-confirm').value = '';
      $('continue-after-backup').hidden = false;
      button.textContent = 'Backup secured';
    } catch (error) {
      console.error('Encrypted backup setup failed:', error);
      showError('recovery-setup-error', error.message || 'Could not secure your signing key.');
      button.disabled = false;
      button.textContent = 'Create encrypted backup';
    }
  });

  $('continue-after-backup').addEventListener('click', showSignInAfterRecovery);
  $('continue-after-restore').addEventListener('click', showSignInAfterRecovery);

  $('restore-cloud-key').addEventListener('click', async () => {
    const button = $('restore-cloud-key');
    showError('restore-error', '');
    $('restore-success').hidden = true;
$('continue-after-restore').hidden = true;
    if (!pendingCloudBackup || !pendingPublicKey) return showError('restore-error', 'No encrypted cloud backup is selected.');
    const password = $('restore-cloud-password').value;

if (!password) {
  return showError(
    'restore-error',
    'Please enter your separate recovery password.'
  );
}
    button.disabled = true;
    button.textContent = 'Decrypting and verifying...';
    try {
      const me = api.currentUser();
      const privateKey = await decryptEncryptedKeyBackup(pendingCloudBackup, password, me.id);
      if (!(await matchesPublicKey(privateKey, pendingPublicKey))) throw new Error('Recovered key does not match the registered public key. Nothing was saved.');
      await savePrivateKey(me.id, await lockPrivateKeyForLocalStorage(privateKey));
      const confirmed = await loadPrivateKey(me.id);
      if (!confirmed || !(await matchesPublicKey(confirmed, pendingPublicKey))) throw new Error('Restored key could not be confirmed in local storage. Keep your backup and retry.');
      $('restore-success').textContent = 'Signing key restored, verified, and saved in this browser.';
      $('restore-success').hidden = false;
      button.textContent = 'Key restored';
      $('continue-after-restore').textContent = 'Sign in';
      $('continue-after-restore').hidden = false;
    } catch (error) {
    console.error('Cloud key recovery rejected:', error);

    const message = /incorrect|modified|decrypt|operationerror/i.test(error.message || '')
        ? 'Recovery rejected: incorrect recovery password or damaged cloud backup. No signing key was restored.'
        : (error.message || 'Could not restore the signing key.');

    $('restore-success').hidden = true;
    $('continue-after-restore').hidden = true;

    showError('restore-error', message);

    button.disabled = false;
    button.textContent = 'Restore from encrypted cloud backup';
}
  });


})();
