/* Attack demo: change a message, replay a message, rewrite the ledger. */
(async function () {
  'use strict';
  if (!App.requireLogin()) return;
  App.mountNav('demo');

  const me = api.currentUser();
  const $ = (id) => document.getElementById(id);

  function optionLabel(m) {
    const text = m.message.length > 46 ? m.message.slice(0, 46) + '…' : m.message;
    return '#' + m.id + ' ' + m.sender + ' → ' + m.receiver + ': ' + text;
  }

  async function fillSelects() {
    const messages = await api.listAllMessages();
    const options = messages.length
      ? messages.map((m) => '<option value="' + m.id + '">' + App.esc(optionLabel(m)) + '</option>').join('')
      : '<option value="">No messages yet</option>';
    $('a1-msg').innerHTML = options;
    $('a2-msg').innerHTML = options;

    const entries = await api.getLedger();
    const failed = entries.filter((e) => e.event === 'VERIFIED' && e.detail.status !== 'GENUINE');
    const others = entries.filter((e) => !failed.includes(e));
    const label = (e, note) => '<option value="' + e.index + '">#' + e.index + ' ' + App.esc(note) + '</option>';
    $('a3-entry').innerHTML = entries.length
      ? failed.map((e) => label(e, 'Failed check: ' + App.meta(e.detail.status).label + ' (' + e.detail.sender + ')')).join('') +
        others.map((e) => label(e, e.event.toLowerCase().replace('_', ' '))).join('')
      : '<option value="">The ledger is empty</option>';
  }

  function note(id, html) { $(id).innerHTML = html; }
  const link = (href, text) => '<a href="' + href + '">' + text + '</a>';

  $('a1-go').addEventListener('click', async () => {
    const id = Number($('a1-msg').value);
    if (!id) return note('a1-out', '<p class="error-text">Choose a message first.</p>');
    const text = $('a1-text').value.trim();
    if (!text) return note('a1-out', '<p class="error-text">Enter the new text first.</p>');
    const result = await api.demoTamperMessage(id, text, $('a1-rehash').checked);
    if (!result.ok) return note('a1-out', '<p class="error-text">' + App.esc(result.error) + '</p>');
    await fillSelects();
    const expected = $('a1-rehash').checked ? 'Invalid signature' : 'Tampered';
    note('a1-out', '<p>Message #' + id + ' changed. ' + link('inbox.html', 'Open the inbox') +
      ' (as the receiver) and check it. Expected result: <strong>' + expected + '</strong>.</p>');
  });

  function rejectionHtml(result) {
    const v = App.meta(result.verdict);
    return '<div class="seal ' + v.cls + '" role="status"><span class="seal-icon" aria-hidden="true">' + v.icon + '</span>' +
      '<div><div class="seal-title">Rejected: ' + v.label + '</div><p>' + v.text + '</p></div></div>' +
      '<p class="fine" style="margin-top:8px">Recorded as an alert. ' + link('ledger.html', 'See it in the ledger') + '.</p>';
  }

  $('a2-replay').addEventListener('click', async () => {
    const id = Number($('a2-msg').value);
    if (!id) return note('a2-out', '<p class="error-text">Choose a message first.</p>');
    note('a2-out', rejectionHtml(await api.demoResubmit(id)));
  });

  $('a2-old').addEventListener('click', async () => {
    const users = await api.listUsers();
    const receiver = users.find((u) => u !== me.username) || 'bob';
    note('a2-out', rejectionHtml(await api.demoSendOld(me.username, receiver, 'This message was signed an hour ago.')));
  });

  $('a3-go').addEventListener('click', async () => {
    const seq = Number($('a3-entry').value);
    if (!seq) return note('a3-out', '<p class="error-text">There is no entry to change yet.</p>');
    const result = await api.demoTamperLedger(seq);
    if (!result.ok) return note('a3-out', '<p class="error-text">' + App.esc(result.error) + '</p>');
    note('a3-out', '<p>Entry #' + seq + ' rewritten. ' + link('ledger.html', 'Open the ledger') +
      ' and choose <strong>Check the chain</strong>. Expected result: broken at entry #' + seq + '.</p>');
  });

  $('reset-sample').addEventListener('click', async () => {
    await api.reset(true);
    await fillSelects();
    App.toast('Sample data restored.');
  });
  $('reset-empty').addEventListener('click', async () => {
    await api.reset(false);
    await fillSelects();
    App.toast('Everything cleared.');
  });

  await fillSelects();
})();
