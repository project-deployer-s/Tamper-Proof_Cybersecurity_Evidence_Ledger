/* Receiver page: list of messages and the verification report. */
(async function () {
  'use strict';
  if (!App.requireLogin()) return;
  App.mountNav('inbox');

  const me = api.currentUser();
  const $ = (id) => document.getElementById(id);
  let messages = [];
  let selectedId = null;
  let lastResult = null; // the report for the selected message, if it was just checked

  /* ---------- list ---------- */
  function renderList() {
    if (!messages.length) {
      $('list').innerHTML =
        '<li class="empty"><strong>No messages yet</strong>Messages sent to ' + App.esc(me.username) + ' appear here.' +
        (me.username !== 'bob' ? ' Sign in as bob to see the sample messages.' : '') + '</li>';
      $('check-all').disabled = true;
      return;
    }
    $('check-all').disabled = !messages.some((m) => !m.lastCheck);
    $('list').innerHTML = messages.map((m) => {
      const verdict = m.lastCheck ? m.lastCheck.verdict : 'PENDING';
      return '<li><button type="button" class="msg-row" data-id="' + m.id + '"' + (m.id === selectedId ? ' aria-current="true"' : '') + '>' +
        '<span class="top"><span class="from">' + App.esc(m.sender) + '</span><span class="when">' + App.fmtTime(m.timestamp) + '</span></span>' +
        '<span class="preview">' + App.esc(m.message) + '</span>' + App.badge(verdict) + '</button></li>';
    }).join('');
  }

  /* ---------- detail ---------- */
  function reportHtml(result) {
    const v = App.meta(result.verdict);
    const marks = { pass: '✓', fail: '✕', skipped: '–' };
    const words = { pass: 'Passed', fail: 'Failed', skipped: 'Not run' };
    const steps = result.checks.map((c) =>
      '<li class="' + c.state + '"><span class="mark" aria-hidden="true">' + marks[c.state] + '</span>' +
      '<span>' + App.esc(c.label) + ' <span class="fine">(' + words[c.state] + ')</span></span></li>').join('');
    return '<div class="seal ' + v.cls + '" role="status"><span class="seal-icon" aria-hidden="true">' + v.icon + '</span>' +
      '<div><div class="seal-title">' + v.label + '</div><p>' + v.text + '</p></div></div>' +
      '<ol class="checks" aria-label="Checks run, in order">' + steps + '</ol>' +
      '<p class="fine" style="margin-top:12px">This check is recorded in the ledger as entry #' + result.ledgerSeq + '.</p>';
  }

  function renderDetail() {
    const m = messages.find((x) => x.id === selectedId);
    if (!m) {
      $('detail').innerHTML = '<div class="empty"><strong>Select a message</strong>You will see who sent it and can check that it is genuine.</div>';
      return;
    }
    let report = '';
    if (lastResult && lastResult.messageId === m.id) {
      report = reportHtml(lastResult);
    } else if (m.lastCheck) {
      report = '<p>Last checked ' + App.fmtTime(m.lastCheck.checkedAt) + ': ' + App.badge(m.lastCheck.verdict) +
        ' (ledger entry #' + m.lastCheck.ledgerSeq + ')</p>';
    }
    $('detail').innerHTML =
      '<h2>From ' + App.esc(m.sender) + '</h2>' +
      '<div class="msg-body">' + App.esc(m.message) + '</div>' +
      '<dl class="facts">' +
        '<dt>Sent</dt><dd>' + App.fmtTime(m.timestamp) + '</dd>' +
        '<dt>One-time number</dt><dd class="mono">' + App.esc(m.nonce) + '</dd>' +
        '<dt>Recorded hash</dt><dd class="mono">' + App.esc(m.hash) + '</dd>' +
      '</dl>' +
      '<div class="row" style="margin-bottom:16px"><button class="btn" type="button" id="check-btn" data-id="' + m.id + '">' +
        (m.lastCheck ? 'Check again' : 'Check this message') + '</button></div>' +
      '<div id="report">' + report + '</div>';
  }

  async function refresh() {
    messages = await api.getInbox(me.username);
    renderList();
    renderDetail();
  }

  async function runCheck(id) {
    const result = await api.verify(id);
    lastResult = result;
    return result;
  }

  /* ---------- events ---------- */
  $('list').addEventListener('click', (e) => {
    const row = e.target.closest('.msg-row');
    if (!row) return;
    selectedId = Number(row.dataset.id);
    lastResult = null;
    renderList();
    renderDetail();
  });

  $('detail').addEventListener('click', async (e) => {
    const button = e.target.closest('#check-btn');
    if (!button) return;
    button.disabled = true;
    button.textContent = 'Checking…';
    try {
      await runCheck(Number(button.dataset.id));
      await refresh();
    } catch (err) {
      App.toast(err.message, 'bad');
      button.disabled = false;
      button.textContent = 'Check this message';
    }
  });

  $('check-all').addEventListener('click', async (e) => {
    const button = e.currentTarget;
    button.disabled = true;
    const pending = messages.filter((m) => !m.lastCheck);
    for (const m of pending) { await runCheck(m.id); }
    await refresh();
    App.toast('Checked ' + pending.length + ' message' + (pending.length === 1 ? '' : 's') + '.');
  });

  await refresh();
})();
