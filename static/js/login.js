/* Sign in, create account, and key setup. */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);

  const tabs = { signin: $('tab-signin'), signup: $('tab-signup') };
  const panes = { signin: $('pane-signin'), signup: $('pane-signup') };

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
    const result = await api.login($('si-user').value, $('si-pass').value);
    if (!result.ok) return showError('si-error', result.error);
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
    if (!result.ok) return showError('su-error', result.error);
    // Account created: move on to key setup.
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
    // Generate actual ECDSA P-256 keys.
    const keyPair = await generateKeyPair();

    // Export public and private keys.
    const publicKeyBuffer = await exportPublicKey(keyPair.publicKey);
    const privateKeyBuffer = await exportPrivateKey(keyPair.privateKey);

    const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);
    backupText = arrayBufferToBase64(privateKeyBuffer);

    // Register only the public key with Flask.
    const result = await api.registerPublicKey(publicKeyBase64);

    if (!result.ok) {
      throw new Error(result.error);
    }

const me = api.currentUser();
await savePrivateKey(me.id, keyPair.privateKey);

    // Calculate SHA-256 fingerprint.
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

// Download the private key only when the user clicks.
$('download-key').addEventListener('click', () => {
  if (!backupText) {
    App.toast('No private key backup available.');
    return;
  }

  downloadPrivateKey(backupText);
  App.toast('Private key backup downloaded.');
});

  $('download-key').addEventListener('click', () => {
    const blob = new Blob([backupText], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'evidence-ledger-key-backup.txt';
    link.click();
    URL.revokeObjectURL(link.href);
    App.toast('Backup downloaded.');
  });
})();
