
/* ======================================================================
   Shared helpers used by every page: navigation, verdict wording,
   formatting and toasts. Page-specific code lives in the other files.
   ====================================================================== */
(function () {
  'use strict';

  const VERDICTS = {
    GENUINE: {
      icon: '✓',
      label: 'Genuine',
      cls: 'ok',
      text: 'The signature is valid and the content is unchanged.'
    },
    TAMPERED: {
      icon: '✕',
      label: 'Tampered',
      cls: 'bad',
      text: 'The content no longer matches the hash recorded when it was sent. Someone changed it.'
    },
    INVALID_SIGNATURE: {
      icon: '✕',
      label: 'Invalid signature',
      cls: 'bad',
      text: 'The content was changed and the hash was rewritten to hide it, but the signature does not match. This is what a forgery looks like.'
    },
    UNKNOWN_SENDER: {
      icon: '?',
      label: 'Unknown sender',
      cls: 'mute',
      text: 'No public key is registered for this sender, so the message cannot be trusted.'
    },
    REVOKED_KEY: {
      icon: '⊘',
      label: 'Revoked key',
      cls: 'warn',
      text: 'The sender had already revoked this key when the message was signed. Treat it as stolen.'
    },
    REPLAY: {
      icon: '↻',
      label: 'Replay',
      cls: 'warn',
      text: 'This exact message was already submitted once. The server rejected the copy.'
    },
    EXPIRED: {
      icon: '◔',
      label: 'Expired',
      cls: 'warn',
      text: 'The timestamp is too old. The server rejected the message.'
    },
    PENDING: {
      icon: '•',
      label: 'Not checked',
      cls: 'mute',
      text: 'Open the message and run the check.'
    }
  };

  const App = { VERDICTS };

  App.esc = (value) =>
    String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
    );

  App.fmtTime = (ts) => {
    if (!ts) return 'Unknown time';

    let date;

    if (typeof ts === 'number' || /^\d+(\.\d+)?$/.test(String(ts))) {
      const value = Number(ts);
      date = new Date(value < 1e12 ? value * 1000 : value);
    } else {
      date = new Date(ts);
    }

    if (Number.isNaN(date.getTime())) return 'Unknown time';

    return date.toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true
    }) + ' IST';
  };

  App.short = (hash, n) => (hash ? hash.slice(0, n || 10) + '…' : '');

  App.meta = (verdict) => VERDICTS[verdict] || VERDICTS.PENDING;

  App.badge = (verdict) => {
    const m = App.meta(verdict);
    return '<span class="badge ' + m.cls + '">' +
      '<span aria-hidden="true">' + m.icon + '</span>' +
      m.label + '</span>';
  };

  App.toast = (message, kind) => {
    const box = document.getElementById('toasts');
    if (!box) return;

    const el = document.createElement('div');
    el.className = 'toast' + (kind === 'bad' ? ' bad' : '');
    el.textContent = message;
    box.appendChild(el);
    setTimeout(() => el.remove(), 3600);
  };

  App.requireLogin = () => {
    if (!api.currentUser()) {
      location.replace('index.html');
      return false;
    }
    return true;
  };

  const NAV = [
    { id: 'inbox', href: 'inbox.html', label: 'Inbox' },
    { id: 'send', href: 'send.html', label: 'Send a message' },
    { id: 'ledger', href: 'ledger.html', label: 'Ledger and alerts' },
    { id: 'demo', href: 'demo.html', label: 'Attack demo' }
  ];

  App.mountNav = (active) => {
    const rail = document.getElementById('rail');
    const me = api.currentUser();

    if (!rail || !me) return;

    const links = NAV.map((n) =>
      '<li><a href="' + n.href + '"' +
      (n.id === active ? ' aria-current="page"' : '') +
      '>' + n.label + '</a></li>'
    ).join('');

    rail.innerHTML =
      '<div class="brand">' +
        '<svg width="26" height="26" viewBox="0 0 26 26" fill="none" stroke="#fff" stroke-width="2.4" aria-hidden="true">' +
        '<rect x="2" y="8" width="14" height="10" rx="5"/>' +
        '<rect x="10" y="8" width="14" height="10" rx="5"/>' +
        '</svg>' +
        'Evidence Ledger</div>' +
      '<ul class="nav">' + links + '</ul>' +
      '<div class="who">Signed in as <strong>' +
        App.esc(me.username) +
        '</strong><span class="role">' +
        App.esc(me.role) +
        '</span><br>' +
        '<button class="link-btn" id="signout" type="button">Sign out</button>' +
        '<p class="proto">Prototype with sample data</p></div>';

    document.getElementById('signout').addEventListener('click', () => {
      api.logout();
      location.href = 'index.html';
    });
  };

  window.App = App;
})();
