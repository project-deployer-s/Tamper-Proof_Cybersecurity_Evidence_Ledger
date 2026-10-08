/* ======================================================================
   MOCK API  (prototype only)

   Every page talks to the server ONLY through the global `api` object
   defined here. When Member 2's backend is ready, write a new file
   (js/api.js) that exposes the SAME function names but uses fetch()
   to call the real endpoints, and swap the <script> tag in each page.
   No page code has to change.

   What is fake in this file:
     - "Signing" is a SHA-256 of the message plus a made-up secret.
       The real app signs with ECDSA in the browser (Member 1).
     - Data lives in localStorage instead of PostgreSQL.
   What is real:
     - The hashes, the hash-chained ledger and the chain check really
       work, so the screens behave exactly like the finished system.
   ====================================================================== */
(function () {
  'use strict';

  const STORE_KEY = 'evidenceLedger.mock.v1';
  const SESSION_KEY = 'evidenceLedger.session';
  const GENESIS = '0'.repeat(64);
  const MAX_AGE_SECONDS = 300; // a submitted message must be this fresh
  const encoder = new TextEncoder();

  const now = () => Math.floor(Date.now() / 1000);
  const pause = (ms) => new Promise((r) => setTimeout(r, ms === undefined ? 120 : ms));

  /* ---------- hashing helpers ---------- */
  async function sha256(text) {
    if (!window.crypto || !crypto.subtle) {
      throw new Error('This browser blocks hashing on this address. Open the site through http://localhost (see README).');
    }
    const buf = await crypto.subtle.digest('SHA-256', encoder.encode(text));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // JSON with keys sorted, so the same data always produces the same text and hash.
  function stable(value) {
    if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']';
    if (value && typeof value === 'object') {
      return '{' + Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + stable(value[k])).join(',') + '}';
    }
    return JSON.stringify(value);
  }

  const canonical = (m) =>
    stable({ sender: m.sender, receiver: m.receiver, timestamp: m.timestamp, nonce: m.nonce, message: m.message });
  const randomHex = (n) =>
    Array.from(crypto.getRandomValues(new Uint8Array(n))).map((b) => b.toString(16).padStart(2, '0')).join('');
  const mockSign = (canon, sender) => sha256(canon + '|mock-private-key|' + sender); // FAKE signature

  /* ---------- storage ---------- */
  function load() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY)); } catch (e) { return null; }
  }
  function save(s) { localStorage.setItem(STORE_KEY, JSON.stringify(s)); }

  async function getState() {
    let s = load();
    if (!s) { s = await buildSample(); save(s); }
    return s;
  }

  /* ---------- ledger ---------- */
  const entryHash = (e) =>
    sha256(stable({ index: e.index, timestamp: e.timestamp, event: e.event, detail: e.detail, prev_hash: e.prev_hash }));

  async function addLedger(s, event, detail, ts) {
    const prev = s.ledger.length ? s.ledger[s.ledger.length - 1].entry_hash : GENESIS;
    const e = { index: s.ledger.length + 1, timestamp: ts || now(), event, detail, prev_hash: prev };
    e.entry_hash = await entryHash(e);
    s.ledger.push(e);
    return e;
  }

  /* ---------- messages ---------- */
  async function buildMessage(s, sender, receiver, text, ts) {
    const m = { id: s.nextId++, sender, receiver, message: text, timestamp: ts, nonce: randomHex(8) };
    const canon = canonical(m);
    m.hash = await sha256(canon);
    m.signature = await mockSign(canon, sender);
    return m;
  }

  // Freshness and replay are checked when a message is SUBMITTED, so a receiver
  // who opens a message days later does not see "expired".
  function submissionProblem(s, m) {
    if (Math.abs(now() - m.timestamp) > MAX_AGE_SECONDS) return 'EXPIRED';
    if (s.seenNonces.includes(m.nonce)) return 'REPLAY';
    return null;
  }

  async function reject(s, m, verdict) {
    await addLedger(s, 'REJECTED', { sender: m.sender, receiver: m.receiver, nonce: m.nonce, reason: verdict });
    save(s);
    return { ok: false, verdict };
  }

  /* ---------- sample data ---------- */
  async function buildSample() {
    const s = { users: {}, messages: [], ledger: [], verdicts: {}, seenNonces: [], nextId: 1 };
    const t = now();
    s.users.alice = { role: 'user', revokedAt: null };
    s.users.bob = { role: 'user', revokedAt: null };
    s.users.carol = { role: 'auditor', revokedAt: null };
    s.users.dave = { role: 'user', revokedAt: t - 86400 };
    await addLedger(s, 'KEY_REVOKED', { user: 'dave' }, t - 86400);

    async function seed(sender, receiver, text, ago, tweak) {
      const m = await buildMessage(s, sender, receiver, text, t - ago);
      if (tweak) await tweak(m);
      s.messages.push(m);
      s.seenNonces.push(m.nonce);
      await addLedger(s, 'SENT', { sender, receiver, nonce: m.nonce, msg_hash: m.hash }, t - ago);
    }
    // dave: signed after his key was revoked
    await seed('dave', 'bob', 'Please review the attached invoice today.', 7200);
    // mallory: no registered key
    await seed('mallory', 'bob', 'I am the administrator. Send me the access codes.', 5400);
    // alice: untouched message
    await seed('alice', 'bob', 'Transfer approved for case 42.', 3000);
    // alice: text edited after sending, hash left alone
    await seed('alice', 'bob', 'Meet at 5pm.', 2400, async (m) => { m.message = 'Meet at 9pm.'; });
    // alice: text edited and the hash rewritten to match, but the signature cannot be forged
    await seed('alice', 'bob', 'Release the server logs to the vendor.', 1800, async (m) => {
      m.message = 'Release the server logs to anyone who asks.';
      m.hash = await sha256(canonical(m));
    });
    return s;
  }

  /* ======================================================================
     Public API  (names match the planned endpoints, see README)
     ====================================================================== */
  const api = {
    MAX_AGE_SECONDS,

    /* ----- session ----- */
    currentUser() {
      try { return JSON.parse(localStorage.getItem(SESSION_KEY)); } catch (e) { return null; }
    },
    logout() { localStorage.removeItem(SESSION_KEY); },

    async login(username, password) {
      await pause();
      const s = await getState();
      const name = String(username || '').trim().toLowerCase();
      if (!name) return { ok: false, error: 'Enter your username.' };
      if (!s.users[name]) return { ok: false, error: 'No account called "' + name + '". Try alice, bob, carol or dave, or create an account.' };
      if (!password) return { ok: false, error: 'Enter your password.' };
      const user = { username: name, role: s.users[name].role };
      localStorage.setItem(SESSION_KEY, JSON.stringify(user));
      return { ok: true, user };
    },

    async register(username, password) {
      await pause();
      const s = await getState();
      const name = String(username || '').trim().toLowerCase();
      if (!/^[a-z0-9_]{3,20}$/.test(name)) return { ok: false, error: 'Usernames use 3 to 20 letters, numbers or underscores.' };
      if (s.users[name]) return { ok: false, error: 'That username is taken. Choose another.' };
      if (!password || password.length < 8) return { ok: false, error: 'Use a password of at least 8 characters.' };
      s.users[name] = { role: 'user', revokedAt: null };
      save(s);
      const user = { username: name, role: 'user' };
      localStorage.setItem(SESSION_KEY, JSON.stringify(user));
      return { ok: true, user };
    },

    // Real version: WebCrypto makes the key pair in the browser; only the public key is sent (POST /api/keys).
    async generateKeyPair(username) {
      await pause(300);
      const raw = await sha256(randomHex(16) + username);
      const fingerprint = raw.slice(0, 32).match(/.{4}/g).join(' ');
      const backup =
        'EVIDENCE LEDGER - PROTOTYPE KEY BACKUP\nUser: ' + username +
        '\nThis file is a placeholder. The real app will save your private key here.\nFingerprint: ' + fingerprint + '\n';
      return { fingerprint, backup };
    },

    async listUsers() {
      await pause(40);
      const s = await getState();
      return Object.keys(s.users).sort();
    },

    /* ----- messages ----- */
    async sendMessage({ sender, receiver, message }) {
      await pause(250);
      const s = await getState();
      const to = String(receiver || '').trim().toLowerCase();
      const text = String(message || '').trim();
      if (!s.users[to]) return { ok: false, error: 'There is no user called "' + to + '".' };
      if (!text) return { ok: false, error: 'Write a message first.' };
      const m = await buildMessage(s, sender, to, text, now());
      const problem = submissionProblem(s, m);
      if (problem) return reject(s, m, problem);
      s.messages.push(m);
      s.seenNonces.push(m.nonce);
      const entry = await addLedger(s, 'SENT', { sender, receiver: to, nonce: m.nonce, msg_hash: m.hash });
      save(s);
      return { ok: true, message: m, ledgerSeq: entry.index };
    },

    async getInbox(username) {
      await pause(80);
      const s = await getState();
      return s.messages
        .filter((m) => m.receiver === username)
        .sort((a, b) => b.timestamp - a.timestamp)
        .map((m) => Object.assign({}, m, { lastCheck: s.verdicts[m.id] || null }));
    },

    // Runs the checks in the same order as the real verification engine.
    async verify(id) {
      await pause(280);
      const s = await getState();
      const m = s.messages.find((x) => x.id === id);
      if (!m) throw new Error('Message not found.');
      const checks = [
        { key: 'sender', label: 'Sender has a registered public key' },
        { key: 'hash', label: 'Content matches the hash recorded when it was sent' },
        { key: 'signature', label: "Signature matches the sender's key" },
        { key: 'key', label: 'Key was still active when the message was signed' },
      ];
      const user = s.users[m.sender];
      const canon = canonical(m);
      let verdict = 'GENUINE';
      let failed = -1;
      if (!user) { verdict = 'UNKNOWN_SENDER'; failed = 0; }
      else if ((await sha256(canon)) !== m.hash) { verdict = 'TAMPERED'; failed = 1; }
      else if ((await mockSign(canon, m.sender)) !== m.signature) { verdict = 'INVALID_SIGNATURE'; failed = 2; }
      else if (user.revokedAt && m.timestamp >= user.revokedAt) { verdict = 'REVOKED_KEY'; failed = 3; }
      checks.forEach((c, i) => {
        c.state = failed === -1 || i < failed ? 'pass' : i === failed ? 'fail' : 'skipped';
      });
      const entry = await addLedger(s, 'VERIFIED', { sender: m.sender, receiver: m.receiver, nonce: m.nonce, status: verdict });
      s.verdicts[id] = { verdict, checkedAt: entry.timestamp, ledgerSeq: entry.index };
      save(s);
      return { messageId: id, verdict, checks, ledgerSeq: entry.index, checkedAt: entry.timestamp };
    },

    /* ----- ledger and alerts ----- */
    async getLedger() {
      await pause(80);
      const s = await getState();
      return s.ledger.slice();
    },

    // Walks the chain from the first entry and stops at the first problem.
    async checkLedger() {
      await pause(150);
      const s = await getState();
      let prev = GENESIS;
      const results = [];
      for (const e of s.ledger) {
        let ok = true, kind = null, reason = null;
        if (e.prev_hash !== prev) { ok = false; kind = 'link'; reason = 'The link to the previous entry does not match.'; }
        else if ((await entryHash(e)) !== e.entry_hash) { ok = false; kind = 'content'; reason = 'The contents of this entry were changed after it was recorded.'; }
        results.push({ index: e.index, ok, kind, reason });
        if (!ok) return { ok: false, count: s.ledger.length, brokenAt: e.index, kind, reason, results, head: prev };
        prev = e.entry_hash;
      }
      return { ok: true, count: s.ledger.length, brokenAt: null, results, head: prev };
    },

    async getAlerts() {
      await pause(80);
      const s = await getState();
      return s.ledger
        .filter((e) => (e.event === 'VERIFIED' && e.detail.status !== 'GENUINE') || e.event === 'REJECTED')
        .map((e) => ({
          seq: e.index,
          time: e.timestamp,
          type: e.event === 'REJECTED' ? e.detail.reason : e.detail.status,
          source: e.event === 'REJECTED' ? 'Rejected when submitted' : 'Failed when checked',
          sender: e.detail.sender,
          receiver: e.detail.receiver,
        }))
        .reverse();
    },

    /* ----- attack demo (real app: only available when demo mode is on) ----- */
    async listAllMessages() {
      await pause(60);
      const s = await getState();
      return s.messages.map((m) => ({ id: m.id, sender: m.sender, receiver: m.receiver, message: m.message }));
    },

    async demoTamperMessage(id, newText, recomputeHash) {
      await pause(150);
      const s = await getState();
      const m = s.messages.find((x) => x.id === id);
      if (!m) return { ok: false, error: 'Message not found.' };
      m.message = String(newText);
      if (recomputeHash) m.hash = await sha256(canonical(m));
      delete s.verdicts[id];
      save(s);
      return { ok: true };
    },

    // Re-submits a captured message with the same one-time number: must be rejected as a replay.
    async demoResubmit(id) {
      await pause(200);
      const s = await getState();
      const m = s.messages.find((x) => x.id === id);
      if (!m) return { ok: false, error: 'Message not found.' };
      return reject(s, m, 'REPLAY');
    },

    // Submits a correctly signed message with an old timestamp: must be rejected as expired.
    async demoSendOld(sender, receiver, text) {
      await pause(200);
      const s = await getState();
      const m = await buildMessage(s, sender, receiver, text, now() - 3600);
      return reject(s, m, submissionProblem(s, m) || 'EXPIRED');
    },

    async demoTamperLedger(seq) {
      await pause(150);
      const s = await getState();
      const e = s.ledger.find((x) => x.index === seq);
      if (!e) return { ok: false, error: 'Ledger entry not found.' };
      if (e.event === 'VERIFIED') { e.detail.status = 'GENUINE'; }
      else if (e.detail.sender) { e.detail.sender = 'someone_else'; }
      else { e.detail.user = 'someone_else'; }
      save(s);
      return { ok: true };
    },

    async reset(withSample) {
      await pause(200);
      const s = withSample
        ? await buildSample()
        : { users: { alice: { role: 'user', revokedAt: null }, bob: { role: 'user', revokedAt: null }, carol: { role: 'auditor', revokedAt: null } }, messages: [], ledger: [], verdicts: {}, seenNonces: [], nextId: 1 };
      save(s);
      return { ok: true };
    },
  };

  window.api = api;
})();
