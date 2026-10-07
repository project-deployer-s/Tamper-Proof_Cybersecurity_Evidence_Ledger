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
    const result = await api.register($('su-user').value, $('su-pass').value);
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
    button.textContent = 'Creating key…';
    const me = api.currentUser();
    const key = await api.generateKeyPair(me.username);
    backupText = key.backup;
    $('fingerprint').textContent = key.fingerprint;
    $('key-result').hidden = false;
    button.textContent = 'Key created';
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
