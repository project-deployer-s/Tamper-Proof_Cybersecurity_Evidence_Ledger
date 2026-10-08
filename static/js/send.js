/* Sender page: compose, sign and send. */
(async function () {
  'use strict';
  if (!App.requireLogin()) return;
  App.mountNav('send');

  const me = api.currentUser();
  const $ = (id) => document.getElementById(id);

  // Fill the "To" list with everyone except the signed-in user.
  const users = (await api.listUsers()).filter((u) => u !== me.username);
  $('to').innerHTML = users.map((u) => '<option value="' + App.esc(u) + '">' + App.esc(u) + '</option>').join('');
  if (users.includes('bob')) $('to').value = 'bob';

  $('body').addEventListener('input', () => { $('count').textContent = $('body').value.length; });

  function showError(message) {
    $('send-error').textContent = message;
    $('send-error').hidden = !message;
  }

  $('send-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('');
    $('outcome').innerHTML = '';
    const button = $('send-btn');
    button.disabled = true;
    button.textContent = 'Signing…';

    const result = await api.sendMessage({ sender: me.username, receiver: $('to').value, message: $('body').value });
    button.disabled = false;
    button.textContent = 'Sign and send';

    if (!result.ok && result.error) return showError(result.error);

    if (!result.ok) {
      // The server refused the message (replay or expired).
      const v = App.meta(result.verdict);
      $('outcome').innerHTML =
        '<div class="seal ' + v.cls + '" role="status"><span class="seal-icon" aria-hidden="true">' + v.icon + '</span>' +
        '<div><div class="seal-title">Message rejected: ' + v.label + '</div><p>' + v.text + '</p></div></div>';
      return;
    }

    const m = result.message;
    $('outcome').innerHTML =
      '<div class="seal ok" role="status"><span class="seal-icon" aria-hidden="true">✓</span>' +
      '<div><div class="seal-title">Sent to ' + App.esc(m.receiver) + '</div>' +
      '<p>Signed and recorded in the ledger as entry #' + result.ledgerSeq + '.</p></div></div>' +
      '<div class="panel" style="margin-top:16px"><h2 style="margin-bottom:10px">What was signed</h2>' +
      '<dl class="facts">' +
        '<dt>From</dt><dd>' + App.esc(m.sender) + '</dd>' +
        '<dt>To</dt><dd>' + App.esc(m.receiver) + '</dd>' +
        '<dt>Time</dt><dd>' + App.fmtTime(m.timestamp) + '</dd>' +
        '<dt>One-time number</dt><dd class="mono">' + App.esc(m.nonce) + '</dd>' +
        '<dt>Content hash</dt><dd class="mono">' + App.esc(m.hash) + '</dd>' +
      '</dl>' +
      '<p class="fine">The one-time number stops anyone from sending a captured copy of this message again.</p>' +
      '<a class="btn secondary" href="ledger.html">See it in the ledger</a></div>';
    $('body').value = '';
    $('count').textContent = '0';
  });
})();
