
/* Real database-backed Ledger and Alerts page */
(async function () {
  'use strict';

  if (!App.requireLogin()) return;
  App.mountNav('ledger');

  const $ = (id) => document.getElementById(id);

  let entries = [];
  let alerts = [];

  const EVENT_LABEL = {
    SENT: 'Message sent',
    VERIFIED: 'Message verified',
    REJECTED: 'Submission rejected',
    KEY_REVOKED: 'Key revoked'
  };

  function formatTime(value) {
    if (!value) return 'Unknown time';

    const date = new Date(value);

    return Number.isNaN(date.getTime())
      ? 'Unknown time'
      : date.toLocaleString();
  }

  function summarize(entry) {
    const detail = entry.detail || {};

    if (entry.event_type === 'KEY_REVOKED') {
      return App.esc(detail.user || 'A user') + ' revoked a key';
    }

    const sender = detail.sender || 'Unknown sender';
    const receiver = detail.receiver || 'Unknown receiver';

    return App.esc(sender) + ' → ' + App.esc(receiver);
  }

  function blockHtml(entry) {
    const detail = entry.detail || {};

    let badge = '';

    if (entry.event_type === 'VERIFIED') {
      badge = App.badge(detail.verdict || detail.status || 'PENDING');
    }

    return `
      <li class="block" data-index="${entry.seq}">
        <span class="seq">#${entry.seq}</span>

        <div>
          <div class="ev">
            ${App.esc(EVENT_LABEL[entry.event_type] || entry.event_type)}
            ${badge}
          </div>

          <div class="sum">
            ${summarize(entry)}
            · ${App.esc(formatTime(entry.created_at))}
          </div>
        </div>

        <div class="hashes">
          <div>
            <span>hash</span>
            ${App.esc(App.short(entry.entry_hash, 12))}
          </div>

          <div>
            <span>prev</span>
            ${App.esc(App.short(entry.prev_hash, 12))}
          </div>
        </div>
      </li>
    `;
  }

  function renderChain() {
    const chain = $('chain');

    if (!entries.length) {
      chain.innerHTML =
        '<li class="empty panel"><strong>The ledger is empty</strong>Send a message and it will appear here.</li>';

      $('summary').textContent = '';
      $('check-chain').disabled = true;
      return;
    }

    $('check-chain').disabled = false;

    const latest = entries[0];

    $('summary').innerHTML =
      entries.length +
      ' entries. Latest hash: <span class="mono">' +
      App.esc(latest.entry_hash.slice(0, 24)) +
      '…</span>';

    chain.innerHTML = entries.map((entry, index) => {
      const link = entries[index + 1];

      return blockHtml(entry) +
        (link
          ? `<li class="link" aria-hidden="true">
               <span>#${entry.seq} stores the hash of #${link.seq}</span>
             </li>`
          : '');
    }).join('');
  }

  async function loadLedger() {
    $('chain').innerHTML =
      '<li class="empty panel">Loading ledger entries...</li>';

    const result = await api.getLedger();

    if (!result.ok) {
      $('chain').innerHTML =
        '<li class="empty panel">Unable to load ledger: ' +
        App.esc(result.error) + '</li>';

      $('check-chain').disabled = true;
      return;
    }

    entries = result.data.entries || [];

    // Backend returns newest first. Keep that order for display.
    renderChain();
  }

  function clearMarks() {
    document.querySelectorAll('.block, .link').forEach((element) => {
      element.classList.remove('is-ok', 'is-broken', 'is-unchecked');
    });

    $('banner').hidden = true;
  }

  async function checkChain() {
    const button = $('check-chain');

    button.disabled = true;
    button.textContent = 'Checking...';

    clearMarks();

    const result = await api.checkLedger();

    const banner = $('banner');
    banner.hidden = false;

    if (result.ok && result.data.integrity === 'VALID') {
      banner.className = 'banner ok';

      banner.innerHTML =
        'Chain intact<p>' +
        App.esc(result.data.message || 'All ledger entries passed verification.') +
        '</p>';

      document.querySelectorAll('.block').forEach((element) => {
        element.classList.add('is-ok');
      });

    } else {
      const message = result.data?.message || result.error ||
        'Ledger integrity verification failed.';

      banner.className = 'banner bad';

      banner.innerHTML =
        'Chain integrity check failed<p>' +
        App.esc(message) +
        '</p>';

      document.querySelectorAll('.block').forEach((element) => {
        element.classList.add('is-unchecked');
      });
    }

    button.disabled = false;
    button.textContent = 'Check the chain';
  }

  $('check-chain').addEventListener('click', checkChain);

  $('copy-head').addEventListener('click', async () => {
    if (!entries.length) return;

    const hash = entries[0].entry_hash;

    try {
      await navigator.clipboard.writeText(hash);
      App.toast('Latest hash copied.');
    } catch {
      App.toast('Could not copy the hash.', 'bad');
    }
  });

  async function renderAlerts() {
    $('alerts').innerHTML =
      '<div class="panel empty">Loading alerts...</div>';

    const result = await api.getAlerts();

    if (!result.ok) {
      $('alerts').innerHTML =
        '<div class="panel empty">Unable to load alerts: ' +
        App.esc(result.error) + '</div>';
      return;
    }

    alerts = result.data.alerts || [];

    if (!alerts.length) {
      $('alerts').innerHTML =
        '<div class="panel empty"><strong>No alerts</strong>Failed verification checks appear here.</div>';
      return;
    }

    $('alerts').innerHTML = `
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Entry</th>
              <th>When</th>
              <th>Problem</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>

          <tbody>
            ${alerts.map((alert) => `
              <tr>
                <td class="mono">#${alert.ledger_seq}</td>
                <td>${App.esc(formatTime(alert.created_at))}</td>
                <td>${App.esc(alert.alert_type)}</td>
                <td>${App.esc(alert.severity)}</td>
                <td>${alert.acknowledged ? 'Acknowledged' : 'Unacknowledged'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function showView(name) {
    const isLedger = name === 'ledger';

    $('tab-ledger').setAttribute('aria-selected', String(isLedger));
    $('tab-alerts').setAttribute('aria-selected', String(!isLedger));

    $('view-ledger').hidden = !isLedger;
    $('view-alerts').hidden = isLedger;

    if (!isLedger) {
      renderAlerts();
    }
  }

  $('tab-ledger').addEventListener('click', () => showView('ledger'));
  $('tab-alerts').addEventListener('click', () => showView('alerts'));

  await loadLedger();

})();
