
/* Real backend inbox and message verification */
(async function () {
  'use strict';

  if (!App.requireLogin()) return;

  App.mountNav('inbox');

  const me = api.currentUser();
  const $ = (id) => document.getElementById(id);

  let messages = [];
  let selectedId = null;
  let lastResult = null;

  function showError(message) {
    App.toast(message || 'Something went wrong.', 'bad');
  }

  function renderList() {
    if (!messages.length) {
      $('list').innerHTML =
        '<li class="empty"><strong>No messages yet</strong>' +
        'Messages sent to ' + App.esc(me.username) +
        ' will appear here.</li>';

      $('check-all').disabled = true;
      return;
    }

    $('check-all').disabled =
      !messages.some(m => m.verification_status === 'PENDING');

    $('list').innerHTML = messages.map(m => {
      const verdict = m.verification_status || 'PENDING';

      return `
        <li>
          <button type="button"
            class="msg-row"
            data-id="${Number(m.id)}"
            ${Number(m.id) === selectedId ? 'aria-current="true"' : ''}>
            <span class="top">
              <span class="from">${App.esc(m.sender)}</span>
              <span class="when">${App.fmtTime(m.timestamp)}</span>
            </span>
            <span class="preview">${App.esc(m.message)}</span>
            ${App.badge(verdict)}
          </button>
        </li>
      `;
    }).join('');
  }

  function renderDetail() {
    const m = messages.find(x => Number(x.id) === selectedId);

    if (!m) {
      $('detail').innerHTML =
        '<div class="empty"><strong>Select a message</strong>' +
        'You can inspect and verify the selected message here.</div>';
      return;
    }

    let report = '';

    if (lastResult && Number(lastResult.message_id) === Number(m.id)) {
      report = `
        <div class="seal">
          <div class="seal-title">
            ${App.esc(lastResult.verdict)}
          </div>
          <p>Verification result recorded in the ledger.</p>
          <p class="fine">
            Ledger entry #${Number(lastResult.ledger_seq)}
          </p>
        </div>
      `;
    }

    $('detail').innerHTML = `
      <h2>From ${App.esc(m.sender)}</h2>

      <div class="msg-body">${App.esc(m.message)}</div>

      <dl class="facts">
        <dt>Sent</dt>
        <dd>${App.fmtTime(m.timestamp)}</dd>

        <dt>One-time number</dt>
        <dd class="mono">${App.esc(m.nonce)}</dd>

        <dt>Content hash</dt>
        <dd class="mono">${App.esc(m.content_hash)}</dd>

        <dt>Status</dt>
        <dd>${App.badge(m.verification_status || 'PENDING')}</dd>
      </dl>

      <div class="row" style="margin-bottom:16px">
        <button class="btn" type="button" id="check-btn"
          data-id="${Number(m.id)}">
          Verify message
        </button>
      </div>

      <div id="report">${report}</div>
    `;
  }

  async function refresh() {
    const result = await api.getInbox();

    if (!result.ok) {
      throw new Error(result.error);
    }

    messages = result.data.messages || [];

    if (
      selectedId !== null &&
      !messages.some(m => Number(m.id) === selectedId)
    ) {
      selectedId = null;
      lastResult = null;
    }

    renderList();
    renderDetail();
  }

  async function runCheck(id) {
    const result = await api.verify(id);

    if (!result.ok) {
      throw new Error(result.error);
    }

    lastResult = result.data;
  }

  $('list').addEventListener('click', event => {
    const row = event.target.closest('.msg-row');

    if (!row) return;

    selectedId = Number(row.dataset.id);
    lastResult = null;

    renderList();
    renderDetail();
  });

  $('detail').addEventListener('click', async event => {
    const button = event.target.closest('#check-btn');

    if (!button) return;

    button.disabled = true;
    button.textContent = 'Verifying...';

    try {
      await runCheck(Number(button.dataset.id));
      await refresh();
      renderDetail();
      App.toast('Verification completed.');
    } catch (error) {
      showError(error.message);
      button.disabled = false;
      button.textContent = 'Verify message';
    }
  });

  $('check-all').addEventListener('click', async event => {
    const button = event.currentTarget;

    button.disabled = true;

    const pending = messages.filter(
      m => m.verification_status === 'PENDING'
    );

    let checked = 0;
    let failed = 0;

    for (const message of pending) {
      try {
        await runCheck(Number(message.id));
        checked++;
      } catch (error) {
        failed++;
      }
    }

    try {
      await refresh();

      App.toast(
        `Verified ${checked} message(s). ${failed} failed.`,
        failed ? 'bad' : 'success'
      );
    } catch (error) {
      showError(error.message);
      button.disabled = false;
    }
  });

  try {
    await refresh();
  } catch (error) {
    showError(error.message);
  }
})();
