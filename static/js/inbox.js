
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

  function isExpired(message) {
    if (typeof message.is_expired === 'boolean') {
      return message.is_expired;
    }

    return Boolean(
      message.expires_at &&
      Date.now() >= new Date(message.expires_at).getTime()
    );
  }

  function formatExpiry(message) {
    if (!message.expires_at) return 'Never expires';

    return App.fmtTime(message.expires_at);
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

    $('check-all').disabled = !messages.some(
      m => !isExpired(m) &&
      m.verification_status === 'PENDING'
    );

    $('list').innerHTML = messages.map(m => {
      const expired = isExpired(m);
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

            <span class="preview">
              ${expired
                ? 'Message Expired'
                : App.esc(m.message)}
            </span>

            ${expired
              ? '<span class="hint">Expired</span>'
              : App.badge(verdict)}
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

    const expired = isExpired(m);
    const attachments = m.attachments || [];

    const attachmentHTML = !expired && attachments.length
      ? `
        <div class="attachment-section">
          <h3>Attachments (${attachments.length})</h3>

          ${attachments.map(a => `
            <div class="attachment-item">
              <div>
                <strong>${App.esc(a.filename)}</strong>
                <p class="fine">
                  ${(a.file_size / 1024).toFixed(2)} KB
                </p>
              </div>

              <button
                class="btn download-attachment"
                type="button"
                data-url="${App.esc(a.download_url)}"
                data-filename="${App.esc(a.filename)}">
                Download
              </button>
            </div>
          `).join('')}
        </div>
      `
      : '';

    let report = '';

    if (
      lastResult &&
      Number(lastResult.message_id) === Number(m.id)
    ) {
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

    const messageContent = expired
      ? `
        <div class="seal" role="status">
          <div class="seal-title">Message Expired</div>
          <p>
            This message is no longer available.
            Its cryptographic evidence remains preserved in the ledger.
          </p>
        </div>
      `
      : `
        <div class="msg-body">${App.esc(m.message)}</div>
        ${attachmentHTML}
      `;

    $('detail').innerHTML = `
      <h2>From ${App.esc(m.sender)}</h2>

      ${messageContent}

      <dl class="facts">
        <dt>Sent</dt>
        <dd>${App.fmtTime(m.timestamp)}</dd>

        <dt>Availability</dt>
        <dd>${App.esc(formatExpiry(m))}</dd>

        <dt>One-time number</dt>
        <dd class="mono">${App.esc(m.nonce)}</dd>

        <dt>Content hash</dt>
        <dd class="mono">${App.esc(m.content_hash)}</dd>

        <dt>Status</dt>
        <dd>${App.badge(m.verification_status || 'PENDING')}</dd>
      </dl>

      ${expired ? '' : `
        <div class="row" style="margin-bottom:16px">
          <button class="btn" type="button" id="check-btn"
            data-id="${Number(m.id)}">
            Verify message
          </button>
        </div>
      `}

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
    const downloadButton =
      event.target.closest('.download-attachment');

    if (downloadButton) {
      downloadButton.disabled = true;
      downloadButton.textContent = 'Downloading...';

      const result = await api.downloadAttachment(
        downloadButton.dataset.url,
        downloadButton.dataset.filename
      );

      if (!result.ok) {
        showError(result.error);
      }

      downloadButton.disabled = false;
      downloadButton.textContent = 'Download';

      return;
    }

    const button = event.target.closest('#check-btn');

    if (!button) return;

    const selected = messages.find(
      m => Number(m.id) === Number(button.dataset.id)
    );

    if (!selected || isExpired(selected)) {
      showError('This message has expired.');
      return;
    }

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
      m => !isExpired(m) &&
      m.verification_status === 'PENDING'
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
