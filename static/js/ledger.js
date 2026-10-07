/* Ledger page: the hash chain, the chain check, and the alerts list. */
(async function () {
  'use strict';
  if (!App.requireLogin()) return;
  App.mountNav('ledger');

  const $ = (id) => document.getElementById(id);
  const EVENT_LABEL = { SENT: 'Message sent', VERIFIED: 'Message checked', REJECTED: 'Submission rejected', KEY_REVOKED: 'Key revoked' };
  let entries = [];

  function summarize(e) {
    const d = e.detail;
    if (e.event === 'KEY_REVOKED') return App.esc(d.user) + ' revoked their key';
    const route = App.esc(d.sender) + ' → ' + App.esc(d.receiver);
    const nonce = d.nonce ? ', number ' + App.esc(d.nonce.slice(0, 8)) : '';
    return route + nonce;
  }

  function blockHtml(e) {
    const badge = e.event === 'VERIFIED' ? App.badge(e.detail.status)
      : e.event === 'REJECTED' ? App.badge(e.detail.reason) : '';
    return '<li class="block" data-index="' + e.index + '">' +
      '<span class="seq">#' + e.index + '</span>' +
      '<div><div class="ev">' + EVENT_LABEL[e.event] + ' ' + badge + '</div>' +
        '<div class="sum">' + summarize(e) + ' · ' + App.fmtTime(e.timestamp) + '</div></div>' +
      '<div class="hashes"><div><span>hash</span>' + App.short(e.entry_hash, 12) + '</div>' +
        '<div><span>prev</span>' + App.short(e.prev_hash, 12) + '</div></div></li>';
  }

  function renderChain() {
    if (!entries.length) {
      $('chain').innerHTML = '<li class="empty panel"><strong>The ledger is empty</strong>Send a message and it will appear here.</li>';
      $('summary').textContent = '';
      $('check-chain').disabled = true;
      return;
    }
    $('check-chain').disabled = false;
    const head = entries[entries.length - 1];
    $('summary').innerHTML = entries.length + ' entries. Latest hash: <span class="mono">' + App.esc(head.entry_hash.slice(0, 24)) + '…</span>';
    // Newest first. A thin connector sits between two entries and shows the link.
    const newestFirst = entries.slice().reverse();
    $('chain').innerHTML = newestFirst.map((e, i) => {
      const older = newestFirst[i + 1];
      const link = older
        ? '<li class="link" aria-hidden="true" data-between="' + older.index + '"><span>#' + e.index + ' stores the hash of #' + older.index + '</span></li>'
        : '';
      return blockHtml(e) + link;
    }).join('');
  }

  function clearMarks() {
    document.querySelectorAll('.block, .link').forEach((el) => el.classList.remove('is-ok', 'is-broken', 'is-unchecked'));
    $('banner').hidden = true;
  }

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const wait = (ms) => new Promise((r) => setTimeout(r, reduceMotion ? 0 : ms));

  // Walks the chain from the oldest entry, marking each one, and stops at the first break.
  async function checkChain() {
    const button = $('check-chain');
    button.disabled = true;
    button.textContent = 'Checking…';
    clearMarks();
    const report = await api.checkLedger();

    for (const r of report.results) {
      const block = document.querySelector('.block[data-index="' + r.index + '"]');
      const link = document.querySelector('.link[data-between="' + (r.index - 1) + '"]');
      if (r.ok) {
        if (link) link.classList.add('is-ok');
        block.classList.add('is-ok');
        await wait(70);
      } else {
        if (r.kind === 'link' && link) link.classList.add('is-broken');
        if (link && r.kind === 'link') link.querySelector('span').textContent = 'link broken here';
        block.classList.add('is-broken');
        block.scrollIntoView({ block: 'center', behavior: reduceMotion ? 'auto' : 'smooth' });
      }
    }
    if (!report.ok) {
      document.querySelectorAll('.block').forEach((b) => {
        if (Number(b.dataset.index) > report.brokenAt) b.classList.add('is-unchecked');
      });
    }

    const banner = $('banner');
    banner.hidden = false;
    if (report.ok) {
      banner.className = 'banner ok';
      banner.innerHTML = 'Chain intact<p>All ' + report.count + ' entries match. Nothing has been changed since it was recorded.</p>';
    } else {
      banner.className = 'banner bad';
      banner.innerHTML = 'Chain broken at entry #' + report.brokenAt +
        '<p>' + App.esc(report.reason) + ' Entries after #' + report.brokenAt + ' cannot be trusted until this is explained.</p>';
    }
    button.disabled = false;
    button.textContent = 'Check the chain';
  }

  $('check-chain').addEventListener('click', checkChain);

  $('copy-head').addEventListener('click', async () => {
    if (!entries.length) return;
    const hash = entries[entries.length - 1].entry_hash;
    try {
      await navigator.clipboard.writeText(hash);
      App.toast('Latest hash copied. Publish it somewhere the server cannot edit.');
    } catch (e) {
      App.toast('Could not copy. Latest hash: ' + hash, 'bad');
    }
  });

  /* ---------- alerts ---------- */
  async function renderAlerts() {
    const alerts = await api.getAlerts();
    if (!alerts.length) {
      $('alerts').innerHTML = '<div class="panel empty"><strong>No alerts</strong>Failed checks and rejected submissions appear here.</div>';
      return;
    }
    $('alerts').innerHTML = '<div class="table-wrap"><table><thead><tr><th>Entry</th><th>When</th><th>Problem</th><th>How it was caught</th><th>From</th><th>To</th></tr></thead><tbody>' +
      alerts.map((a) =>
        '<tr><td class="mono">#' + a.seq + '</td><td>' + App.fmtTime(a.time) + '</td><td>' + App.badge(a.type) + '</td><td>' +
        App.esc(a.source) + '</td><td>' + App.esc(a.sender) + '</td><td>' + App.esc(a.receiver) + '</td></tr>').join('') +
      '</tbody></table></div>';
  }

  /* ---------- tabs ---------- */
  function showView(name) {
    const isLedger = name === 'ledger';
    $('tab-ledger').setAttribute('aria-selected', isLedger);
    $('tab-alerts').setAttribute('aria-selected', !isLedger);
    $('view-ledger').hidden = !isLedger;
    $('view-alerts').hidden = isLedger;
    if (!isLedger) renderAlerts();
  }
  $('tab-ledger').addEventListener('click', () => showView('ledger'));
  $('tab-alerts').addEventListener('click', () => showView('alerts'));

  entries = await api.getLedger();
  renderChain();
})();
