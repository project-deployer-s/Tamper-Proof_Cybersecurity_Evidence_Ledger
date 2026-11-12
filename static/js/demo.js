/* Attack Demonstrations - explanatory frontend for isolated backend simulations */
(async function () {
  'use strict';

  if (!App.requireLogin()) return;
  App.mountNav('demo');

  const attackIds = [
    'tampering',
    'forged_signature',
    'replay',
    'expired',
    'revoked_key'
  ];

  // One global control collapses the investigation to its compact default view.
  let tamperCollapsedAll = false;
  const collapsedDemoWindows = Object.create(null);

  function renderGlobalDemoWindow(id, content, label = 'Investigation') {
    const collapsed = Boolean(collapsedDemoWindows[id]);
    return `
      <div class="demo-global-window" data-demo-window="${esc(id)}">
        <div class="demo-global-toolbar">
          <span class="demo-small-note">${esc(label)}</span>
          <button class="demo-global-toggle" type="button" data-global-window-toggle="${esc(id)}" aria-label="${collapsed ? 'Expand' : 'Collapse'} window" title="${collapsed ? 'Expand' : 'Collapse'}"><span aria-hidden="true">${collapsed ? '⌄' : '⌃'}</span></button>
        </div>
        <div class="demo-global-window-content${collapsed ? ' is-collapsed' : ''}">${content}</div>
      </div>`;
  }

  const esc = (value) => App.esc(value == null ? '—' : String(value));
  const statusLabel = (status) => ({
    passed: 'Passed',
    failed: 'Failed',
    not_reached: 'Not reached'
  }[status] || 'Unknown');

  function statusClass(status) {
    if (status === 'passed') return 'demo-status-passed';
    if (status === 'failed') return 'demo-status-failed';
    return 'demo-status-muted';
  }

  function renderSeal(result) {
    const detected = Boolean(result.detected);
    return `
      <div class="demo-verdict ${detected ? 'is-detected' : 'is-unexpected'}" role="status">
        <span class="demo-verdict-icon">${detected ? '✓' : '!'}</span>
        <div>
          <strong>${detected ? 'Attack detected as expected' : 'Unexpected verification result'}</strong>
          <p>${esc(result.message || result.explanation)}</p>
        </div>
      </div>`;
  }

  function renderKeyValue(label, value, extraClass = '') {
    return `
      <div class="demo-kv">
        <span>${esc(label)}</span>
        <strong class="${extraClass}">${esc(value)}</strong>
      </div>`;
  }

  function renderMessageComparison(result) {
    const scenario = result.scenario || {};
    const attacker = result.attacker || {};
    const integrity = result.integrity || {};
    const original = scenario.original_message;
    const submitted = scenario.submitted_message;

    return `
      <section class="demo-section">
        <h3>1. What happened?</h3>
        <p class="demo-explanation">${esc(result.description)}</p>
        <div class="demo-action-box">
          <span class="demo-section-label">Attacker's action</span>
          <p>${esc(attacker.action)}</p>
        </div>
        <div class="demo-two-columns">
          <div class="demo-data-card">
            <span class="demo-section-label">Original signed message</span>
            <p class="demo-message">${esc(original)}</p>
          </div>
          <div class="demo-data-card ${original !== submitted ? 'demo-data-changed' : ''}">
            <span class="demo-section-label">Message submitted for verification</span>
            <p class="demo-message">${esc(submitted)}</p>
          </div>
        </div>
        <div class="demo-hash-grid">
          ${renderKeyValue('Original content hash', integrity.original_content_hash, 'demo-hash')}
          ${renderKeyValue('Submitted content hash', integrity.submitted_content_hash, 'demo-hash')}
          ${renderKeyValue('Content hash matches', integrity.content_hash_matches ? 'Yes' : 'No',
            integrity.content_hash_matches ? 'demo-text-good' : 'demo-text-bad')}
          ${renderKeyValue('Signature valid for sender', integrity.signature_valid_for_sender ? 'Yes' : 'No',
            integrity.signature_valid_for_sender ? 'demo-text-good' : 'demo-text-bad')}
        </div>
      </section>`;
  }

  function renderScenarioDetails(result) {
    const scenario = result.scenario || {};
    const attacker = result.attacker || {};
    return `
      <section class="demo-section">
        <h3>Scenario details</h3>
        <div class="demo-kv-grid">
          ${renderKeyValue('Claimed sender', scenario.sender)}
          ${renderKeyValue('Receiver', scenario.receiver)}
          ${renderKeyValue('Timestamp', scenario.original_timestamp)}
          ${renderKeyValue('Nonce', scenario.nonce, 'demo-hash')}
          ${renderKeyValue('Freshness window', scenario.freshness_window_seconds != null
            ? `${scenario.freshness_window_seconds} seconds` : 'Not applicable')}
          ${renderKeyValue('Unrelated signing key used', attacker.used_unrelated_signing_key ? 'Yes' : 'No')}
          ${renderKeyValue('Nonce reused', attacker.reused_nonce ? 'Yes' : 'No')}
          ${renderKeyValue('Revoked key used', attacker.used_revoked_key ? 'Yes' : 'No')}
        </div>
      </section>`;
  }

  function renderVerificationSteps(result) {
    const steps = Array.isArray(result.verification_steps) ? result.verification_steps : [];
    return `
      <section class="demo-section">
        <h3>2. How the system checked it</h3>
        <ol class="demo-timeline">
          ${steps.map((step, index) => `
            <li class="demo-timeline-item">
              <span class="demo-timeline-marker ${statusClass(step.status)}">${step.status === 'passed' ? '✓' : step.status === 'failed' ? '✕' : '–'}</span>
              <div class="demo-timeline-content">
                <div class="demo-timeline-heading">
                  <strong>${index + 1}. ${esc(step.title)}</strong>
                  <span class="demo-status ${statusClass(step.status)}">${esc(statusLabel(step.status))}</span>
                </div>
                <p>${esc(step.explanation)}</p>
                ${step.technical_detail ? `<code>${esc(step.technical_detail)}</code>` : ''}
              </div>
            </li>`).join('')}
        </ol>
      </section>`;
  }

  function renderEvidence(result) {
    const evidence = result.evidence || {};
    const safety = result.safety || {};
    return `
      <section class="demo-section">
        <h3>3. Demonstration result and evidence</h3>
        <div class="demo-evidence-card">
          ${renderKeyValue('Demo evidence ID', evidence.evidence_id, 'demo-hash')}
          ${renderKeyValue('Permanent ledger entry', evidence.recorded ? 'Yes' : 'No',
            evidence.recorded ? 'demo-text-good' : 'demo-text-warn')}
          ${renderKeyValue('Evidence storage', evidence.storage)}
          <p class="demo-small-note">${esc(evidence.note)}</p>
        </div>
        <div class="demo-safety-grid">
          <span>Simulation only: <strong>${safety.is_simulation ? 'Yes' : 'No'}</strong></span>
          <span>Real user data used: <strong>${safety.uses_real_user_data ? 'Yes' : 'No'}</strong></span>
          <span>Permanent ledger modified: <strong>${safety.modifies_production_ledger ? 'Yes' : 'No'}</strong></span>
        </div>
        <p class="demo-final-explanation">${esc(result.explanation)}</p>
      </section>`;
  }

  function renderAttackResult(id, result) {
    const container = document.getElementById('result-' + id);
    if (!container) return;

    const content = `
      <div class="demo-result">
        ${renderSeal(result)}
        <div class="demo-verdict-strip">
          ${renderKeyValue('Expected verdict', result.expected_verdict)}
          ${renderKeyValue('Actual verdict', result.actual_verdict, result.detected ? 'demo-text-good' : 'demo-text-bad')}
        </div>
        ${renderMessageComparison(result)}
        ${renderScenarioDetails(result)}
        ${renderVerificationSteps(result)}
        ${renderEvidence(result)}
      </div>`;
    container.innerHTML = renderGlobalDemoWindow(id, content, 'Investigation result');
  }

  function renderLedgerResult(result) {
    const container = document.getElementById('result-ledger-tampering');
    const simple = result.simple_tampering || {};
    const advanced = result.advanced_tampering || {};

    const content = `
      <div class="demo-result">
        <div class="demo-verdict ${simple.detected && advanced.detected ? 'is-detected' : 'is-unexpected'}" role="status">
          <span class="demo-verdict-icon">${simple.detected && advanced.detected ? '✓' : '!'}</span>
          <div>
            <strong>${simple.detected && advanced.detected ? 'Both tampering attempts detected' : 'Unexpected ledger simulation result'}</strong>
            <p>This test uses disposable sample entries and a simulated trusted snapshot. It does not change the permanent ledger.</p>
          </div>
        </div>

        <section class="demo-section">
          <h3>Scenario A — Direct record modification</h3>
          <p class="demo-explanation">The attacker changes a ledger entry but leaves its original stored hash untouched.</p>
          <div class="demo-two-columns">
            <div class="demo-data-card">
              <span class="demo-section-label">Original record</span>
              <pre>${esc(JSON.stringify((simple.original_entry || {}).detail || {}, null, 2))}</pre>
            </div>
            <div class="demo-data-card demo-data-changed">
              <span class="demo-section-label">Modified record</span>
              <pre>${esc(JSON.stringify((simple.modified_entry || {}).detail || {}, null, 2))}</pre>
            </div>
          </div>
          ${renderKeyValue('Detection result', simple.result)}
          <p>${esc(simple.explanation)}</p>
        </section>

        <section class="demo-section">
          <h3>Scenario B — Rewritten local hash chain</h3>
          <p class="demo-explanation">The attacker changes the record and recalculates the local chain. The chain can look internally consistent, but its final hash no longer matches the previously trusted snapshot.</p>
          <div class="demo-kv-grid">
            ${renderKeyValue('Local hash chain valid', advanced.local_chain_valid ? 'Yes' : 'No',
              advanced.local_chain_valid ? 'demo-text-good' : 'demo-text-bad')}
            ${renderKeyValue('Trusted snapshot matches', advanced.external_anchor_matches ? 'Yes' : 'No',
              advanced.external_anchor_matches ? 'demo-text-good' : 'demo-text-bad')}
            ${renderKeyValue('Trusted snapshot hash', advanced.trusted_anchor, 'demo-hash')}
            ${renderKeyValue('Rewritten chain head', advanced.modified_chain_head, 'demo-hash')}
            ${renderKeyValue('Detection result', advanced.result)}
          </div>
          <p>${esc(advanced.explanation)}</p>
        </section>

        <section class="demo-section">
          <h3>What this proves</h3>
          <ul class="demo-bullet-list">
            <li>A stored hash can reveal an entry changed without recalculating its hash.</li>
            <li>A locally consistent rewritten chain still needs an independently protected reference hash.</li>
            <li>This is a simulated trusted snapshot, not a live external anchor service.</li>
          </ul>
          <div class="demo-safety-grid">
            <span>Simulation: <strong>${esc(result.simulation_type)}</strong></span>
            <span>Permanent ledger modified: <strong>${result.permanent_ledger_modified ? 'Yes' : 'No'}</strong></span>
            <span>Trusted anchor: <strong>${esc(result.trusted_anchor_type)}</strong></span>
          </div>
        </section>
      </div>`;
    container.innerHTML = renderGlobalDemoWindow('ledger-tampering', content, 'Ledger investigation');
  }

  // Message Tampering is intentionally manual and stateful.
  let tamperSessionId = null;
  let tamperState = {
    prepared: false,
    submitted: false,
    hashChecked: false,
    signatureChecked: false,
    completed: false
  };

  function renderTamperWizard() {
    const output = document.getElementById('result-tampering');
    if (!output) return;

    if (!tamperState.prepared) {
      output.innerHTML = `
        <div class="tamper-wizard">
          <p class="demo-explanation">Prepare a fresh sample message and signature. You decide when to perform each next step.</p>
          <button class="btn danger" id="tamper-prepare" type="button">1. Prepare Original Message</button>
          <p class="demo-small-note">This creates a demo-only ECDSA key pair and signs the sample message. No attack has happened yet.</p>
        </div>`;
      return;
    }

    const original = tamperState.original;
    const submitted = tamperState.submitted;
    output.innerHTML = `
      <div class="tamper-wizard">
        <div class="tamper-global-toolbar">
          <span class="demo-small-note">Manual investigation · ${tamperState.completed ? 'Completed' : 'In progress'}</span>
          <button class="demo-global-toggle" id="tamper-toggle-all" type="button"
            aria-label="${tamperCollapsedAll ? 'Expand all steps' : 'Collapse all steps'}"
            title="${tamperCollapsedAll ? 'Expand all' : 'Collapse all'}">
            <span aria-hidden="true">${tamperCollapsedAll ? '⌄' : '⌃'}</span>
          </button>
        </div>
        <div class="tamper-steps-container">
        <div class="tamper-progress">
          <span class="${tamperState.prepared ? 'is-done' : ''}">1. Prepare</span>
          <span class="${tamperState.submitted ? 'is-done' : ''}">2. Tamper</span>
          <span class="${tamperState.hashChecked ? 'is-done' : ''}">3. Hash check</span>
          <span class="${tamperState.signatureChecked ? 'is-done' : ''}">4. Signature check</span>
          <span class="${tamperState.completed ? 'is-done' : ''}">5. Evidence</span>
        </div>

        <section class="demo-section">
          <h3>Step 1 — Original signed message</h3>
          <div class="demo-kv-grid">
            ${renderKeyValue('Sender', original.sender)}
            ${renderKeyValue('Receiver', original.receiver)}
            ${renderKeyValue('Timestamp', original.timestamp)}
            ${renderKeyValue('Nonce', original.nonce, 'demo-hash')}
          </div>
          <div class="demo-data-card">
            <span class="demo-section-label">Original message</span>
            <p class="demo-message">${esc(original.original_message)}</p>
          </div>
          <div class="demo-kv-grid">
            ${renderKeyValue('SHA-256 content hash', original.original_content_hash, 'demo-hash')}
            ${renderKeyValue('Signature fingerprint', original.signature_fingerprint, 'demo-hash')}
            ${renderKeyValue('Digital signature created', 'Yes', 'demo-text-good')}
          </div>
          <p class="demo-small-note">${esc(original.explanation)}</p>
        </section>

        <section class="demo-section">
          <h3>Step 2 — Perform the attack manually</h3>
          <p class="demo-explanation">Change the message below. For example, change “₹500” to “₹50,000”. The original signature will remain unchanged.</p>
          <label class="demo-section-label" for="tamper-message-input">Modified message</label>
          <textarea id="tamper-message-input" rows="3" maxlength="2000" ${submitted ? 'disabled' : ''}>${esc(submitted ? submitted.message : original.original_message)}</textarea>
          ${submitted
            ? `<div class="demo-action-box"><strong>Modified message submitted.</strong><p>${esc(submitted.message)}</p><p class="demo-small-note">The original signature was kept. Verification has not been run automatically.</p></div>`
            : `<button class="btn danger" id="tamper-submit" type="button">2. Submit My Modified Message</button>`}
        </section>

        ${submitted ? `
        <section class="demo-section">
          <h3>Step 3 — Run the security checks yourself</h3>
          <p class="demo-explanation">Choose each check separately. The server will execute only the check you request.</p>
          <div class="demo-two-columns">
            <div class="demo-data-card">
              <span class="demo-section-label">Content-hash check</span>
              ${tamperState.hashResult
                ? `<strong class="${tamperState.hashResult.passed ? 'demo-text-good' : 'demo-text-bad'}">${tamperState.hashResult.passed ? 'MATCH' : 'MISMATCH'}</strong><p>${esc(tamperState.hashResult.explanation)}</p>`
                : `<p>Compare the submitted message hash with the original signed hash.</p><button class="btn" id="tamper-hash-check" type="button">3. Run Hash Check</button>`}
            </div>
            <div class="demo-data-card">
              <span class="demo-section-label">Digital-signature check</span>
              ${tamperState.signatureResult
                ? `<strong class="${tamperState.signatureResult.passed ? 'demo-text-good' : 'demo-text-bad'}">${tamperState.signatureResult.passed ? 'VALID' : 'INVALID'}</strong><p>${esc(tamperState.signatureResult.explanation)}</p>`
                : `<p>Verify whether the original signature authenticates the modified message.</p><button class="btn" id="tamper-signature-check" type="button">4. Run Signature Check</button>`}
            </div>
          </div>
        </section>` : ''}

        ${tamperState.hashChecked && tamperState.signatureChecked ? `
        <section class="demo-section">
          <h3>Step 4 — Complete the investigation</h3>
          ${tamperState.completed ? renderTamperEvidence() : `<p>Both checks have been run. Generate the final temporary evidence report.</p><button class="btn danger" id="tamper-complete" type="button">5. Generate Evidence Report</button>`}
        </section>` : ''}
        </div>
        <div class="demo-actions-row">
          <button class="btn" id="tamper-reset" type="button">Reset and Start Again</button>
        </div>
      </div>`;

    applyTamperGlobalCollapse(output);
  }

  function applyTamperGlobalCollapse(output) {
    const container = output.querySelector('.tamper-steps-container');
    const button = output.querySelector('#tamper-toggle-all');
    if (!container || !button) return;
    container.classList.toggle('is-globally-collapsed', tamperCollapsedAll);
    button.setAttribute('aria-label', tamperCollapsedAll ? 'Expand all steps' : 'Collapse all steps');
    button.title = tamperCollapsedAll ? 'Expand all' : 'Collapse all';
    button.querySelector('span').textContent = tamperCollapsedAll ? '⌄' : '⌃';
  }

  function renderTamperEvidence() {
    const report = tamperState.finalReport;
    if (!report) return '';
    return `
      <div class="demo-verdict ${report.detected ? 'is-detected' : 'is-unexpected'}">
        <span class="demo-verdict-icon">${report.detected ? '✓' : '!'}</span>
        <div><strong>${esc(report.verdict)}</strong><p>${esc(report.explanation)}</p></div>
      </div>
      <div class="demo-evidence-card">
        ${renderKeyValue('Temporary evidence ID', report.evidence.evidence_id, 'demo-hash')}
        ${renderKeyValue('Permanent ledger entry', 'No', 'demo-text-warn')}
        <p class="demo-small-note">${esc(report.evidence.note)}</p>
      </div>`;
  }

  async function prepareTampering() {
    const button = document.getElementById('tamper-prepare');
    if (button) { button.disabled = true; button.textContent = 'Preparing…'; }
    const response = await api.prepareInteractiveTampering();
    if (!response.ok) {
      toastError(response.error || 'Could not prepare the demo.');
      if (button) { button.disabled = false; button.textContent = '1. Prepare Original Message'; }
      return;
    }
    tamperSessionId = response.data.result.session_id;
    tamperState = {
      prepared: true, submitted: false, hashChecked: false,
      signatureChecked: false, completed: false,
      original: response.data.result
    };
    renderTamperWizard();
  }

  async function submitTampering() {
    const input = document.getElementById('tamper-message-input');
    const button = document.getElementById('tamper-submit');
    if (!input || !button) return;
    button.disabled = true;
    button.textContent = 'Submitting…';
    const response = await api.tamperInteractiveMessage(tamperSessionId, input.value);
    if (!response.ok) {
      alert(response.error || 'Could not submit the modified message.');
      button.disabled = false;
      button.textContent = '2. Submit My Modified Message';
      return;
    }
    tamperState.submitted = { message: response.data.result.submitted_message };
    tamperState.hashChecked = false;
    tamperState.signatureChecked = false;
    renderTamperWizard();
  }

  async function runTamperCheck(checkName) {
    const buttonId = checkName === 'hash' ? 'tamper-hash-check' : 'tamper-signature-check';
    const button = document.getElementById(buttonId);
    if (button) { button.disabled = true; button.textContent = 'Checking…'; }
    const response = await api.runInteractiveTamperingCheck(tamperSessionId, checkName);
    if (!response.ok) {
      alert(response.error || 'Verification check failed.');
      renderTamperWizard();
      return;
    }
    if (checkName === 'hash') {
      tamperState.hashChecked = true;
      tamperState.hashResult = response.data.result;
    } else {
      tamperState.signatureChecked = true;
      tamperState.signatureResult = response.data.result;
    }
    renderTamperWizard();
  }

  async function completeTampering() {
    const button = document.getElementById('tamper-complete');
    if (button) { button.disabled = true; button.textContent = 'Generating…'; }
    const response = await api.completeInteractiveTampering(tamperSessionId);
    if (!response.ok) {
      alert(response.error || 'Could not generate the evidence report.');
      renderTamperWizard();
      return;
    }
    tamperState.completed = true;
    tamperState.finalReport = response.data.result;
    renderTamperWizard();
  }

  function resetTampering() {
    tamperSessionId = null;
    tamperCollapsedAll = false;
    tamperState = {
      prepared: false, submitted: false, hashChecked: false,
      signatureChecked: false, completed: false
    };
    renderTamperWizard();
  }

  function toastError(message) {
    const output = document.getElementById('result-tampering');
    if (output) output.insertAdjacentHTML('afterbegin', `<p class="error-text">${esc(message)}</p>`);
  }

  document.addEventListener('click', (event) => {
    const target = event.target && event.target.closest ? event.target.closest('button') : event.target;
    const id = target && target.id;
    if (id === 'tamper-toggle-all') {
      tamperCollapsedAll = !tamperCollapsedAll;
      const output = document.getElementById('result-tampering');
      if (output) applyTamperGlobalCollapse(output);
      return;
    }
    if (id === 'tamper-prepare') prepareTampering();
    if (id === 'tamper-submit') submitTampering();
    if (id === 'tamper-hash-check') runTamperCheck('hash');
    if (id === 'tamper-signature-check') runTamperCheck('signature');
    if (id === 'tamper-complete') completeTampering();
    if (id === 'tamper-reset') resetTampering();
  });

  renderTamperWizard();



  // Expired Digital Signature: manual staged investigation.
  let expiredSessionId = null;
  let expiredState = { prepared: false, submitted: false, verified: false, completed: false };
  let expiredOriginal = null, expiredVerification = null, expiredReport = null;
  let expiredCollapsedAll = false;

  function renderExpiredWizard() {
    const output = document.getElementById('result-expired');
    if (!output) return;
    if (!expiredState.prepared) {
      output.innerHTML = `<div class="tamper-wizard expired-wizard"><p class="demo-explanation">Prepare a genuinely signed packet whose timestamp is older than the receiver's five-minute freshness window.</p><button class="btn danger" id="expired-prepare" type="button">1. Prepare Expired Signed Packet</button><p class="demo-small-note">Temporary demo-only key and sample message. No real messages are involved.</p></div>`;
      return;
    }
    const sections = `
      <section class="demo-section"><h3>Step 1 — Inspect the signed packet</h3>
        <div class="demo-kv-grid">
          ${renderKeyValue('Sender', expiredOriginal.sender)}
          ${renderKeyValue('Receiver', expiredOriginal.receiver)}
          ${renderKeyValue('Signed timestamp', expiredOriginal.timestamp)}
          ${renderKeyValue('Packet age', `${expiredOriginal.age_seconds} seconds`)}
          ${renderKeyValue('Allowed freshness window', `${expiredOriginal.validity_window_seconds} seconds`)}
          ${renderKeyValue('Content hash', expiredOriginal.content_hash, 'demo-hash')}
          ${renderKeyValue('Signature fingerprint', expiredOriginal.signature_fingerprint, 'demo-hash')}
        </div>
        <div class="demo-data-card"><span class="demo-section-label">Signed message</span><p class="demo-message">${esc(expiredOriginal.message)}</p></div>
        <p class="demo-small-note">${esc(expiredOriginal.explanation)}</p>
      </section>
      <section class="demo-section"><h3>Step 2 — Submit the expired packet</h3>
        ${expiredState.submitted ? `<div class="demo-action-box"><strong>Expired packet submitted.</strong><p>The packet was submitted unchanged. Verification has not run yet.</p></div>` : `<p>Submit the original packet to the receiver without modifying its message, timestamp, hash or signature.</p><button class="btn danger" id="expired-submit" type="button">2. Submit Expired Packet</button>`}
      </section>
      ${expiredState.submitted ? `<section class="demo-section"><h3>Step 3 — Verify signature and freshness</h3>
        ${expiredState.verified ? `<div class="demo-verdict ${expiredVerification.detected ? 'is-detected' : 'is-unexpected'}"><strong>${expiredVerification.detected ? 'Expired packet detected' : 'Unexpected result'}</strong><p>${esc(expiredVerification.explanation)}</p></div><div class="demo-verdict-strip">${renderKeyValue('Cryptographic signature valid', expiredVerification.cryptographic_signature_valid ? 'Yes' : 'No', expiredVerification.cryptographic_signature_valid ? 'demo-text-good' : 'demo-text-bad')}${renderKeyValue('Freshness verdict', expiredVerification.freshness_verdict, 'demo-text-bad')}</div>` : `<p>The receiver checks the signature mathematically and separately checks whether the timestamp is within the permitted freshness window.</p><button class="btn" id="expired-verify" type="button">3. Run Verification</button>`}
      </section>` : ''}
      ${expiredState.verified ? `<section class="demo-section"><h3>Step 4 — Generate the investigation report</h3>
        ${expiredState.completed ? `<div class="demo-verdict ${expiredReport.detected ? 'is-detected' : 'is-unexpected'}"><strong>${esc(expiredReport.verdict)}</strong><p>${esc(expiredReport.explanation)}</p></div><div class="demo-evidence-card">${renderKeyValue('Temporary evidence ID', expiredReport.evidence.evidence_id, 'demo-hash')}${renderKeyValue('Permanent ledger entry', 'No', 'demo-text-warn')}<p class="demo-small-note">${esc(expiredReport.evidence.note)}</p></div>` : `<p>Verification is complete. Generate a temporary evidence report.</p><button class="btn danger" id="expired-complete" type="button">4. Generate Evidence Report</button>`}
      </section>` : ''}`;

    output.innerHTML = `<div class="tamper-wizard expired-wizard">
      <div class="tamper-global-toolbar"><span class="demo-small-note">Manual investigation · ${expiredState.completed ? 'Completed' : 'In progress'}</span><button class="demo-global-toggle" id="expired-toggle-all" type="button" aria-label="${expiredCollapsedAll ? 'Expand all steps' : 'Collapse all steps'}" title="${expiredCollapsedAll ? 'Expand all' : 'Collapse all'}"><span aria-hidden="true">${expiredCollapsedAll ? '⌄' : '⌃'}</span></button></div>
      <div class="tamper-steps-container">${sections}</div>
      <div class="demo-actions-row"><button class="btn" id="expired-reset" type="button">Reset and Start Again</button></div>
    </div>`;
    output.querySelector('.tamper-steps-container').classList.toggle('is-globally-collapsed', expiredCollapsedAll);
  }

  async function runExpiredAction(action, buttonId, label) {
    const button = document.getElementById(buttonId);
    if (button) { button.disabled = true; button.textContent = label; }
    const response = await action.call(api, expiredSessionId);
    if (!response.ok) { alert(response.error || 'Expired-signature investigation step failed.'); renderExpiredWizard(); return null; }
    return response.data.result;
  }
  async function prepareExpired() {
    const button = document.getElementById('expired-prepare');
    if (button) { button.disabled = true; button.textContent = 'Preparing…'; }
    const response = await api.prepareInteractiveExpiredSignature();
    if (!response.ok) { alert(response.error || 'Could not prepare expired-signature demo.'); renderExpiredWizard(); return; }
    expiredOriginal = response.data.result; expiredSessionId = expiredOriginal.session_id; expiredState.prepared = true; renderExpiredWizard();
  }
  async function submitExpired() { const r = await runExpiredAction(api.submitInteractiveExpiredSignature, 'expired-submit', 'Submitting…'); if (!r) return; expiredState.submitted = true; renderExpiredWizard(); }
  async function verifyExpired() { const r = await runExpiredAction(api.verifyInteractiveExpiredSignature, 'expired-verify', 'Verifying…'); if (!r) return; expiredVerification = r; expiredState.verified = true; renderExpiredWizard(); }
  async function completeExpired() { const r = await runExpiredAction(api.completeInteractiveExpiredSignature, 'expired-complete', 'Generating…'); if (!r) return; expiredReport = r; expiredState.completed = true; renderExpiredWizard(); }
  function resetExpired() { expiredSessionId = null; expiredOriginal = null; expiredVerification = null; expiredReport = null; Object.keys(expiredState).forEach(k => expiredState[k] = false); expiredCollapsedAll = false; renderExpiredWizard(); }
  document.addEventListener('click', event => {
    const button = event.target && event.target.closest ? event.target.closest('button') : null;
    const id = button && button.id;
    if (id === 'expired-prepare') prepareExpired();
    if (id === 'expired-submit') submitExpired();
    if (id === 'expired-verify') verifyExpired();
    if (id === 'expired-complete') completeExpired();
    if (id === 'expired-reset') resetExpired();
    if (id === 'expired-toggle-all') { expiredCollapsedAll = !expiredCollapsedAll; renderExpiredWizard(); }
  });
  renderExpiredWizard();


  // Revoked Digital Key: manual staged investigation using an isolated demo key.
  let revokedSessionId = null;
  let revokedState = { prepared: false, revoked: false, submitted: false, verified: false, completed: false };
  let revokedOriginal = null, revokedStatus = null, revokedVerification = null, revokedReport = null;
  let revokedCollapsedAll = false;

  function renderRevokedWizard() {
    const output = document.getElementById('result-revoked_key');
    if (!output) return;
    if (!revokedState.prepared) {
      output.innerHTML = `<div class="tamper-wizard revoked-wizard"><p class="demo-explanation">Prepare a genuinely signed packet, revoke its temporary signing key, and then submit the unchanged packet to see why revoked keys must no longer be trusted.</p><button class="btn danger" id="revoked-prepare" type="button">1. Prepare Signed Packet</button><p class="demo-small-note">Temporary demo-only key and sample message. No real user key or permanent ledger entry is involved.</p></div>`;
      return;
    }

    const sections = `
      <section class="demo-section"><h3>Step 1 — Inspect Alice's signed packet and trusted key</h3>
        <div class="demo-kv-grid">
          ${renderKeyValue('Sender', revokedOriginal.sender)}
          ${renderKeyValue('Receiver', revokedOriginal.receiver)}
          ${renderKeyValue('Signed timestamp', revokedOriginal.timestamp)}
          ${renderKeyValue('Key status before revocation', 'TRUSTED', 'demo-text-good')}
          ${renderKeyValue('Key fingerprint', revokedOriginal.key_fingerprint, 'demo-hash')}
          ${renderKeyValue('Content hash', revokedOriginal.content_hash, 'demo-hash')}
          ${renderKeyValue('Signature fingerprint', revokedOriginal.signature_fingerprint, 'demo-hash')}
        </div>
        <div class="demo-data-card"><span class="demo-section-label">Signed message</span><p class="demo-message">${esc(revokedOriginal.message)}</p></div>
        <p class="demo-small-note">${esc(revokedOriginal.explanation)}</p>
      </section>
      <section class="demo-section"><h3>Step 2 — Revoke Alice's demo signing key</h3>
        ${revokedState.revoked ? `<div class="demo-action-box"><strong>Demo key status: REVOKED</strong><p>${esc(revokedStatus.explanation)}</p></div>` : `<p>Revoke the temporary key in the simulated trust registry. This action does not affect real account keys.</p><button class="btn danger" id="revoked-revoke" type="button">2. Revoke Demo Key</button>`}
      </section>
      ${revokedState.revoked ? `<section class="demo-section"><h3>Step 3 — Submit the previously signed packet</h3>
        ${revokedState.submitted ? `<div class="demo-action-box"><strong>Packet submitted after revocation.</strong><p>The message and signature were not changed. Verification has not run yet.</p></div>` : `<p>Submit the original packet after revocation, without changing its message, timestamp, hash or signature.</p><button class="btn danger" id="revoked-submit" type="button">3. Submit Signed Packet</button>`}
      </section>` : ''}
      ${revokedState.submitted ? `<section class="demo-section"><h3>Step 4 — Verify signature and key status</h3>
        ${revokedState.verified ? `<div class="demo-verdict ${revokedVerification.detected ? 'is-detected' : 'is-unexpected'}"><strong>${revokedVerification.detected ? 'Revoked signing key detected' : 'Unexpected result'}</strong><p>${esc(revokedVerification.explanation)}</p></div><div class="demo-verdict-strip">${renderKeyValue('Cryptographic signature valid', revokedVerification.cryptographic_signature_valid ? 'Yes' : 'No', revokedVerification.cryptographic_signature_valid ? 'demo-text-good' : 'demo-text-bad')}${renderKeyValue('Current key status', revokedVerification.key_status, 'demo-text-bad')}${renderKeyValue('Verification verdict', revokedVerification.verdict, 'demo-text-bad')}</div>` : `<p>The receiver checks the signature mathematically and separately checks whether the signing key is still trusted.</p><button class="btn" id="revoked-verify" type="button">4. Run Verification</button>`}
      </section>` : ''}
      ${revokedState.verified ? `<section class="demo-section"><h3>Step 5 — Generate the investigation report</h3>
        ${revokedState.completed ? `<div class="demo-verdict ${revokedReport.detected ? 'is-detected' : 'is-unexpected'}"><strong>${esc(revokedReport.verdict)}</strong><p>${esc(revokedReport.explanation)}</p></div><div class="demo-evidence-card">${renderKeyValue('Temporary evidence ID', revokedReport.evidence.evidence_id, 'demo-hash')}${renderKeyValue('Permanent ledger entry', 'No', 'demo-text-warn')}<p class="demo-small-note">${esc(revokedReport.evidence.note)}</p></div>` : `<p>Verification is complete. Generate a temporary evidence report.</p><button class="btn danger" id="revoked-complete" type="button">5. Generate Evidence Report</button>`}
      </section>` : ''}`;

    output.innerHTML = `<div class="tamper-wizard revoked-wizard">
      <div class="tamper-global-toolbar"><span class="demo-small-note">Manual investigation · ${revokedState.completed ? 'Completed' : 'In progress'}</span><button class="demo-global-toggle" id="revoked-toggle-all" type="button" aria-label="${revokedCollapsedAll ? 'Expand all steps' : 'Collapse all steps'}" title="${revokedCollapsedAll ? 'Expand all' : 'Collapse all'}"><span aria-hidden="true">${revokedCollapsedAll ? '⌄' : '⌃'}</span></button></div>
      <div class="tamper-steps-container">${sections}</div>
      <div class="demo-actions-row"><button class="btn" id="revoked-reset" type="button">Reset and Start Again</button></div>
    </div>`;
    output.querySelector('.tamper-steps-container').classList.toggle('is-globally-collapsed', revokedCollapsedAll);
  }

  async function runRevokedAction(action, buttonId, label) {
    const button = document.getElementById(buttonId);
    if (button) { button.disabled = true; button.textContent = label; }
    const response = await action.call(api, revokedSessionId);
    if (!response.ok) { alert(response.error || 'Revoked-key investigation step failed.'); renderRevokedWizard(); return null; }
    return response.data.result;
  }
  async function prepareRevoked() {
    const button = document.getElementById('revoked-prepare');
    if (button) { button.disabled = true; button.textContent = 'Preparing…'; }
    const response = await api.prepareInteractiveRevokedKey();
    if (!response.ok) { alert(response.error || 'Could not prepare revoked-key demo.'); renderRevokedWizard(); return; }
    revokedOriginal = response.data.result; revokedSessionId = revokedOriginal.session_id; revokedState.prepared = true; renderRevokedWizard();
  }
  async function revokeDemoKey() { const r = await runRevokedAction(api.revokeInteractiveDemoKey, 'revoked-revoke', 'Revoking…'); if (!r) return; revokedStatus = r; revokedState.revoked = true; renderRevokedWizard(); }
  async function submitRevokedPacket() { const r = await runRevokedAction(api.submitInteractiveRevokedPacket, 'revoked-submit', 'Submitting…'); if (!r) return; revokedState.submitted = true; renderRevokedWizard(); }
  async function verifyRevokedPacket() { const r = await runRevokedAction(api.verifyInteractiveRevokedPacket, 'revoked-verify', 'Verifying…'); if (!r) return; revokedVerification = r; revokedState.verified = true; renderRevokedWizard(); }
  async function completeRevoked() { const r = await runRevokedAction(api.completeInteractiveRevokedKey, 'revoked-complete', 'Generating…'); if (!r) return; revokedReport = r; revokedState.completed = true; renderRevokedWizard(); }
  function resetRevoked() { revokedSessionId = null; revokedOriginal = null; revokedStatus = null; revokedVerification = null; revokedReport = null; Object.keys(revokedState).forEach(k => revokedState[k] = false); revokedCollapsedAll = false; renderRevokedWizard(); }
  document.addEventListener('click', event => {
    const button = event.target && event.target.closest ? event.target.closest('button') : null;
    const id = button && button.id;
    if (id === 'revoked-prepare') prepareRevoked();
    if (id === 'revoked-revoke') revokeDemoKey();
    if (id === 'revoked-submit') submitRevokedPacket();
    if (id === 'revoked-verify') verifyRevokedPacket();
    if (id === 'revoked-complete') completeRevoked();
    if (id === 'revoked-reset') resetRevoked();
    if (id === 'revoked-toggle-all') { revokedCollapsedAll = !revokedCollapsedAll; renderRevokedWizard(); }
  });
  renderRevokedWizard();


  // Ledger Tampering: staged manual modification of an isolated sample chain.
  let ledgerDemoSession = null, ledgerDemoOriginal = null, ledgerDemoTamper = null, ledgerDemoVerification = null, ledgerDemoReport = null;
  let ledgerDemoState = { prepared: false, tampered: false, verified: false, completed: false };
  let ledgerDemoCollapsed = false;

  function renderInteractiveLedgerDemo() {
    const output = document.getElementById('result-ledger-tampering');
    if (!output) return;
    if (!ledgerDemoState.prepared) {
      output.innerHTML = `<div class="tamper-wizard"><p class="demo-explanation">Prepare an isolated hash-chained ledger, manually alter one record, and run integrity verification yourself.</p><button class="btn danger" id="ledger-demo-prepare" type="button">1. Prepare Sample Ledger</button><p class="demo-small-note">Only temporary sample records are used. The permanent evidence ledger is not modified.</p></div>`;
      return;
    }
    const rows = ledgerDemoOriginal.records.map(r => `<div class="demo-data-card"><strong>Record ${r.index} · ${esc(r.event)}</strong><p>${esc(r.details)}</p><div class="demo-kv-grid">${renderKeyValue('Actor',r.actor)}${renderKeyValue('Previous hash',r.previous_hash,'demo-hash')}${renderKeyValue('Stored hash',r.record_hash,'demo-hash')}</div></div>`).join('');
    const sections = `
      <section class="demo-section"><h3>Step 1 — Inspect the original hash chain</h3><p>${esc(ledgerDemoOriginal.explanation)}</p>${rows}</section>
      <section class="demo-section"><h3>Step 2 — Manually modify Record 2</h3>${ledgerDemoState.tampered ? `<div class="demo-action-box"><strong>Record 2 modified</strong><p>${esc(ledgerDemoTamper.original_details)} → ${esc(ledgerDemoTamper.modified_details)}</p><p>${esc(ledgerDemoTamper.explanation)}</p></div>` : `<label class="demo-field-label" for="ledger-demo-edit">New record details</label><textarea id="ledger-demo-edit" rows="3" maxlength="500">Changed evidence details: approval status altered by an unauthorized actor.</textarea><button class="btn danger" id="ledger-demo-tamper" type="button">2. Apply Record Modification</button>`}</section>
      ${ledgerDemoState.tampered ? `<section class="demo-section"><h3>Step 3 — Verify hash and chain integrity</h3>${ledgerDemoState.verified ? `<div class="demo-verdict ${ledgerDemoVerification.detected?'is-detected':'is-unexpected'}"><strong>${ledgerDemoVerification.detected?'Ledger tampering detected':'No tampering detected'}</strong><p>${esc(ledgerDemoVerification.explanation)}</p></div>${ledgerDemoVerification.records.map(r=>`<div class="demo-kv-grid">${renderKeyValue('Record '+r.index+' hash',r.record_hash_valid?'VALID':'INVALID',r.record_hash_valid?'demo-text-good':'demo-text-bad')}${renderKeyValue('Record '+r.index+' chain link',r.chain_link_valid?'VALID':'INVALID',r.chain_link_valid?'demo-text-good':'demo-text-bad')}</div>`).join('')}`:`<p>Recalculate each record hash and compare it with the stored hash and previous-record link.</p><button class="btn" id="ledger-demo-verify" type="button">3. Verify Ledger Integrity</button>`}</section>` : ''}
      ${ledgerDemoState.verified ? `<section class="demo-section"><h3>Step 4 — Generate evidence report</h3>${ledgerDemoState.completed ? `<div class="demo-verdict ${ledgerDemoReport.detected?'is-detected':'is-unexpected'}"><strong>${esc(ledgerDemoReport.verdict)}</strong><p>${esc(ledgerDemoReport.explanation)}</p></div><div class="demo-evidence-card">${renderKeyValue('Evidence ID',ledgerDemoReport.evidence.evidence_id,'demo-hash')}${renderKeyValue('Permanent ledger entry','No','demo-text-warn')}<p>${esc(ledgerDemoReport.evidence.note)}</p></div>`:`<button class="btn danger" id="ledger-demo-complete" type="button">4. Generate Evidence Report</button>`}</section>` : ''}`;
    output.innerHTML = `<div class="tamper-wizard ledger-demo-wizard"><div class="tamper-global-toolbar"><span class="demo-small-note">Manual investigation · ${ledgerDemoState.completed?'Completed':'In progress'}</span><button class="demo-global-toggle" id="ledger-demo-toggle" type="button" aria-label="${ledgerDemoCollapsed?'Expand window':'Collapse window'}" title="${ledgerDemoCollapsed?'Expand':'Collapse'}"><span aria-hidden="true">${ledgerDemoCollapsed?'⌄':'⌃'}</span></button></div><div class="tamper-steps-container ${ledgerDemoCollapsed?'is-globally-collapsed':''}">${sections}</div><div class="demo-actions-row"><button class="btn" id="ledger-demo-reset" type="button">Reset and Start Again</button></div></div>`;
  }
  async function ledgerDemoRequest(action, label) {
    const response = await action.call(api, ledgerDemoSession);
    if (!response || !response.ok) { alert(response && response.error || label+' failed.'); return null; }
    return response.data.result;
  }
  async function prepareLedgerDemo() {
    const r = await api.prepareInteractiveLedgerTampering();
    if (!r.ok) { alert(r.error || 'Could not prepare sample ledger.'); return; }
    ledgerDemoOriginal=r.data.result; ledgerDemoSession=ledgerDemoOriginal.session_id; ledgerDemoState.prepared=true; renderInteractiveLedgerDemo();
  }
  async function tamperLedgerDemo() {
    const input=document.getElementById('ledger-demo-edit');
    const r=await api.tamperInteractiveLedgerRecord(ledgerDemoSession,input?input.value:'');
    if (!r.ok) { alert(r.error || 'Could not modify record.'); return; }
    ledgerDemoTamper=r.data.result; ledgerDemoState.tampered=true; renderInteractiveLedgerDemo();
  }
  async function verifyLedgerDemo() { const r=await ledgerDemoRequest(api.verifyInteractiveLedgerChain,'Verification'); if(!r)return; ledgerDemoVerification=r; ledgerDemoState.verified=true; renderInteractiveLedgerDemo(); }
  async function completeLedgerDemo() { const r=await ledgerDemoRequest(api.completeInteractiveLedgerTampering,'Report'); if(!r)return; ledgerDemoReport=r; ledgerDemoState.completed=true; renderInteractiveLedgerDemo(); }
  function resetLedgerDemo() { ledgerDemoSession=null;ledgerDemoOriginal=null;ledgerDemoTamper=null;ledgerDemoVerification=null;ledgerDemoReport=null;Object.keys(ledgerDemoState).forEach(k=>ledgerDemoState[k]=false);ledgerDemoCollapsed=false;renderInteractiveLedgerDemo(); }
  document.addEventListener('click',event=>{
    const b=event.target&&event.target.closest?event.target.closest('button'):null;const id=b&&b.id;
    if(id==='ledger-demo-prepare')prepareLedgerDemo();
    if(id==='ledger-demo-tamper')tamperLedgerDemo();
    if(id==='ledger-demo-verify')verifyLedgerDemo();
    if(id==='ledger-demo-complete')completeLedgerDemo();
    if(id==='ledger-demo-reset')resetLedgerDemo();
    if(id==='ledger-demo-toggle'){ledgerDemoCollapsed=!ledgerDemoCollapsed;renderInteractiveLedgerDemo();}
  });
  renderInteractiveLedgerDemo();

  // Replay Attack is a staged, manual investigation using a disposable nonce store.
  let replaySessionId = null;
  let replayState = { prepared: false, accepted: false, submitted: false, verified: false, completed: false };
  let replayOriginal = null;
  let replaySubmission = null;
  let replayVerification = null;
  let replayReport = null;
  let replayCollapsedAll = false;

  function renderReplayWizard() {
    const output = document.getElementById('result-replay');
    if (!output) return;
    if (!replayState.prepared) {
      output.innerHTML = `<div class="replay-wizard"><p class="demo-explanation">Prepare a fresh signed packet. You will accept it once, then manually replay the exact same packet.</p><button class="btn danger" id="replay-prepare" type="button">1. Prepare Original Packet</button><p class="demo-small-note">Temporary demo-only key and nonce. No real messages are involved.</p></div>`;
      return;
    }

    const sections = `
      <section class="demo-section"><h3>Step 1 — Inspect the original signed packet</h3>
        <div class="demo-kv-grid">
          ${renderKeyValue('Sender', replayOriginal.sender)}
          ${renderKeyValue('Receiver', replayOriginal.receiver)}
          ${renderKeyValue('Timestamp', replayOriginal.timestamp)}
          ${renderKeyValue('Nonce', replayOriginal.nonce, 'demo-hash')}
          ${renderKeyValue('Content hash', replayOriginal.content_hash, 'demo-hash')}
          ${renderKeyValue('Signature fingerprint', replayOriginal.signature_fingerprint, 'demo-hash')}
        </div>
        <div class="demo-data-card"><span class="demo-section-label">Signed message</span><p class="demo-message">${esc(replayOriginal.message)}</p></div>
        <p class="demo-small-note">${esc(replayOriginal.explanation)}</p>
      </section>
      <section class="demo-section"><h3>Step 2 — Receive and accept the original packet</h3>
        ${replayState.accepted ? `<div class="demo-verdict is-detected"><strong>Original packet accepted · ${esc(replayOriginal.acceptance.verdict)}</strong><p>${esc(replayOriginal.acceptance.explanation)}</p>${renderKeyValue('Nonce recorded as used', 'Yes', 'demo-text-good')}</div>` : `<p>The receiver verifies the signature and freshness, then records the nonce to prevent this packet from being accepted again.</p><button class="btn" id="replay-accept" type="button">2. Accept Original Packet</button>`}
      </section>
      ${replayState.accepted ? `<section class="demo-section"><h3>Step 3 — Replay the captured packet</h3>
        <p>The attacker resubmits the exact same message, signature, timestamp and nonce. No field is changed.</p>
        ${replayState.submitted ? `<div class="demo-action-box"><strong>Captured packet resubmitted.</strong>${renderKeyValue('Same message', 'Yes')}${renderKeyValue('Same signature', 'Yes')}${renderKeyValue('Same nonce', 'Yes')}<p>${esc(replaySubmission.explanation)}</p></div>` : `<button class="btn danger" id="replay-submit" type="button">3. Resubmit Captured Packet</button>`}
      </section>` : ''}
      ${replayState.submitted ? `<section class="demo-section"><h3>Step 4 — Run replay-protection verification</h3>
        ${replayState.verified ? `<div class="demo-verdict ${replayVerification.detected ? 'is-detected' : 'is-unexpected'}"><strong>${esc(replayVerification.verdict)}</strong><p>${esc(replayVerification.explanation)}</p></div>${renderKeyValue('Nonce already used', replayVerification.nonce_was_already_used ? 'Yes' : 'No', replayVerification.nonce_was_already_used ? 'demo-text-good' : 'demo-text-bad')}` : `<p>Ask the receiver to verify the packet again. The nonce store should identify that this nonce has already been consumed.</p><button class="btn" id="replay-verify" type="button">4. Verify Replayed Packet</button>`}
      </section>` : ''}
      ${replayState.verified ? `<section class="demo-section"><h3>Step 5 — Generate the investigation report</h3>
        ${replayState.completed ? `<div class="demo-verdict ${replayReport.detected ? 'is-detected' : 'is-unexpected'}"><strong>${esc(replayReport.verdict)}</strong><p>${esc(replayReport.explanation)}</p></div><div class="demo-evidence-card">${renderKeyValue('Temporary evidence ID', replayReport.evidence.evidence_id, 'demo-hash')}${renderKeyValue('Permanent ledger entry', 'No', 'demo-text-warn')}<p class="demo-small-note">${esc(replayReport.evidence.note)}</p></div>` : `<p>Verification is complete. Generate a temporary evidence report for this investigation.</p><button class="btn danger" id="replay-complete" type="button">5. Generate Evidence Report</button>`}
      </section>` : ''}`;

    output.innerHTML = `<div class="tamper-wizard replay-wizard">
      <div class="tamper-global-toolbar"><span class="demo-small-note">Manual investigation · ${replayState.completed ? 'Completed' : 'In progress'}</span><button class="demo-global-toggle" id="replay-toggle-all" type="button" aria-label="${replayCollapsedAll ? 'Expand all steps' : 'Collapse all steps'}" title="${replayCollapsedAll ? 'Expand all' : 'Collapse all'}"><span aria-hidden="true">${replayCollapsedAll ? '⌄' : '⌃'}</span></button></div>
      <div class="tamper-steps-container">${sections}</div>
      <div class="demo-actions-row"><button class="btn" id="replay-reset" type="button">Reset and Start Again</button></div>
    </div>`;
    const container = output.querySelector('.tamper-steps-container');
    container.classList.toggle('is-globally-collapsed', replayCollapsedAll);
  }

  async function runReplayAction(action, buttonId, label) {
    const button = document.getElementById(buttonId);
    if (button) { button.disabled = true; button.textContent = label; }
    const response = await action.call(api, replaySessionId);
    if (!response.ok) { alert(response.error || 'Replay investigation step failed.'); renderReplayWizard(); return null; }
    return response.data.result;
  }

  async function prepareReplay() {
    const button = document.getElementById('replay-prepare');
    if (button) { button.disabled = true; button.textContent = 'Preparing…'; }
    const response = await api.prepareInteractiveReplay();
    if (!response.ok) { alert(response.error || 'Could not prepare replay demo.'); renderReplayWizard(); return; }
    replayOriginal = response.data.result; replaySessionId = replayOriginal.session_id; replayState.prepared = true; renderReplayWizard();
  }
  async function acceptReplay() { const r = await runReplayAction(api.acceptInteractiveReplay, 'replay-accept', 'Accepting…'); if (!r) return; replayOriginal.acceptance = r; replayState.accepted = true; renderReplayWizard(); }
  async function submitReplay() { const r = await runReplayAction(api.submitInteractiveReplay, 'replay-submit', 'Submitting…'); if (!r) return; replaySubmission = r; replayState.submitted = true; renderReplayWizard(); }
  async function verifyReplay() { const r = await runReplayAction(api.verifyInteractiveReplay, 'replay-verify', 'Verifying…'); if (!r) return; replayVerification = r; replayState.verified = true; renderReplayWizard(); }
  async function completeReplay() { const r = await runReplayAction(api.completeInteractiveReplay, 'replay-complete', 'Generating…'); if (!r) return; replayReport = r; replayState.completed = true; renderReplayWizard(); }
  function resetReplay() { replaySessionId = null; replayOriginal = null; replaySubmission = null; replayVerification = null; replayReport = null; Object.keys(replayState).forEach(k => replayState[k] = false); replayCollapsedAll = false; renderReplayWizard(); }
  document.addEventListener('click', event => {
    const button = event.target && event.target.closest ? event.target.closest('button') : null;
    const id = button && button.id;
    if (id === 'replay-prepare') prepareReplay();
    if (id === 'replay-accept') acceptReplay();
    if (id === 'replay-submit') submitReplay();
    if (id === 'replay-verify') verifyReplay();
    if (id === 'replay-complete') completeReplay();
    if (id === 'replay-reset') resetReplay();
    if (id === 'replay-toggle-all') { replayCollapsedAll = !replayCollapsedAll; renderReplayWizard(); }
  });
  renderReplayWizard();

  // Forged Signature is a separate manual investigation, like Message Tampering.
  let forgerySessionId = null;
  const forgeryState = {
    prepared: false, forged: false, submitted: false, verified: false, completed: false
  };
  let forgeryOriginal = null;
  let forgeryCreation = null;
  let forgeryVerification = null;
  let forgeryReport = null;
  let forgeryCollapsedAll = false;

  function renderForgeryWizard() {
    const output = document.getElementById('result-forged_signature');
    if (!output) return;

    if (!forgeryState.prepared) {
      output.innerHTML = `
        <div class="forgery-wizard">
          <p class="demo-explanation">Prepare a sample message that Alice legitimately signs. You will then create and submit a signature made with an unrelated key.</p>
          <button class="btn danger" id="forgery-prepare" type="button">1. Prepare Original Message</button>
          <p class="demo-small-note">All keys are temporary and generated only for this isolated demonstration.</p>
        </div>`;
      return;
    }

    const sections = `
      <section class="demo-section forgery-step">
        <div class="forgery-step-heading">
          <h3>Step 1 — Inspect Alice's original signed message</h3>
        </div>
        <div class="forgery-step-body">
          <div class="demo-kv-grid">
            ${renderKeyValue('Sender', forgeryOriginal.sender)}
            ${renderKeyValue('Receiver', forgeryOriginal.receiver)}
            ${renderKeyValue('Timestamp', forgeryOriginal.timestamp)}
            ${renderKeyValue('Nonce', forgeryOriginal.nonce, 'demo-hash')}
          </div>
          <div class="demo-data-card">
            <span class="demo-section-label">Original message</span>
            <p class="demo-message">${esc(forgeryOriginal.message)}</p>
          </div>
          ${renderKeyValue('Alice signature fingerprint', forgeryOriginal.signature_fingerprint, 'demo-hash')}
          <p class="demo-small-note">${esc(forgeryOriginal.explanation)}</p>
        </div>
      </section>

      <section class="demo-section forgery-step">
        <div class="forgery-step-heading">
          <h3>Step 2 — Create a forged signature</h3>
        </div>
        <div class="forgery-step-body">
          <p class="demo-explanation">The attacker signs the same message using a newly generated private key that is not Alice's key.</p>
          ${forgeryState.forged ? `
            <div class="demo-action-box">
              <strong>Unrelated-key signature created</strong>
              ${renderKeyValue('Forged signature fingerprint', forgeryCreation.signature_fingerprint, 'demo-hash')}
              ${renderKeyValue('Attacker public-key fingerprint', forgeryCreation.attacker_key_fingerprint, 'demo-hash')}
              <p>${esc(forgeryCreation.explanation)}</p>
            </div>
          ` : `<button class="btn danger" id="forgery-create" type="button">2. Generate Forged Signature</button>`}
        </div>
      </section>

      ${forgeryState.forged ? `
      <section class="demo-section forgery-step">
        <div class="forgery-step-heading">
          <h3>Step 3 — Submit the forged signature</h3>
        </div>
        <div class="forgery-step-body">
          <p class="demo-explanation">Submit the message and forged signature while claiming that Alice sent it. The system will not verify it until you request the next step.</p>
          ${forgeryState.submitted
            ? `<div class="demo-action-box"><strong>Forged signature submitted.</strong><p>${esc(forgerySubmitExplanation)}</p></div>`
            : `<button class="btn danger" id="forgery-submit" type="button">3. Submit Forged Signature</button>`}
        </div>
      </section>` : ''}

      ${forgeryState.submitted ? `
      <section class="demo-section forgery-step">
        <div class="forgery-step-heading">
          <h3>Step 4 — Verify the sender's identity</h3>
        </div>
        <div class="forgery-step-body">
          <p class="demo-explanation">The receiver checks the submitted signature against Alice's trusted public key. A second comparison shows which key actually validates it.</p>
          ${forgeryState.verified ? `
            <div class="demo-verdict ${forgeryVerification.detected ? 'is-detected' : 'is-unexpected'}">
              <span class="demo-verdict-icon">${forgeryVerification.detected ? '✓' : '!'}</span>
              <div><strong>${forgeryVerification.detected ? 'Forged signature detected' : 'Unexpected result'}</strong><p>${esc(forgeryVerification.explanation)}</p></div>
            </div>
            <div class="demo-verdict-strip">
              ${renderKeyValue('Valid with Alice trusted key', forgeryVerification.valid_for_sender ? 'Yes' : 'No', forgeryVerification.valid_for_sender ? 'demo-text-good' : 'demo-text-bad')}
              ${renderKeyValue('Valid with attacker key', forgeryVerification.valid_for_attacker ? 'Yes' : 'No', forgeryVerification.valid_for_attacker ? 'demo-text-good' : 'demo-text-bad')}
            </div>
          ` : `<button class="btn" id="forgery-verify" type="button">4. Run Identity Verification</button>`}
        </div>
      </section>` : ''}

      ${forgeryState.verified ? `
      <section class="demo-section forgery-step">
        <div class="forgery-step-heading">
          <h3>Step 5 — Complete the investigation</h3>
        </div>
        <div class="forgery-step-body">
          ${forgeryState.completed ? `
            <div class="demo-verdict ${forgeryReport.detected ? 'is-detected' : 'is-unexpected'}">
              <span class="demo-verdict-icon">${forgeryReport.detected ? '✓' : '!'}</span>
              <div><strong>${esc(forgeryReport.verdict)}</strong><p>${esc(forgeryReport.explanation)}</p></div>
            </div>
            <div class="demo-evidence-card">
              ${renderKeyValue('Temporary evidence ID', forgeryReport.evidence.evidence_id, 'demo-hash')}
              ${renderKeyValue('Permanent ledger entry', 'No', 'demo-text-warn')}
              <p class="demo-small-note">${esc(forgeryReport.evidence.note)}</p>
            </div>
          ` : `<p>Identity verification is complete. Generate a temporary evidence report.</p><button class="btn danger" id="forgery-complete" type="button">5. Generate Evidence Report</button>`}
        </div>
      </section>` : ''}`;

    
      output.innerHTML = `
      <div class="forgery-wizard">
      <div class="tamper-global-toolbar">
      <span class="demo-small-note">
        Manual investigation · ${forgeryState.completed ? 'Completed' : 'In progress'}
      </span>

      <button
        class="demo-global-toggle"
        id="forgery-toggle-all"
        type="button"
        aria-label="${forgeryCollapsedAll ? 'Expand all steps' : 'Collapse all steps'}"
        title="${forgeryCollapsedAll ? 'Expand all' : 'Collapse all'}"
      >
        <span aria-hidden="true">${forgeryCollapsedAll ? '⌄' : '⌃'}</span>
      </button>
      </div>

      <div class="tamper-steps-container ${forgeryCollapsedAll ? 'is-globally-collapsed' : ''}">
      ${sections}
      </div>

      <div class="demo-actions-row">
      <button class="btn" id="forgery-reset" type="button">
        Reset and Start Again
      </button>
      </div>
      </div>`;
    }

  let forgerySubmitExplanation = 'The forged signature was submitted. Verification has not run yet.';

  async function prepareForgery() {
    const button = document.getElementById('forgery-prepare');
    if (button) { button.disabled = true; button.textContent = 'Preparing…'; }
    const response = await api.prepareInteractiveForgery();
    if (!response.ok) {
      alert(response.error || 'Could not prepare the forged-signature demo.');
      renderForgeryWizard();
      return;
    }
    forgerySessionId = response.data.result.session_id;
    forgeryOriginal = response.data.result;
    forgeryState.prepared = true;
    renderForgeryWizard();
  }

  async function createForgery() {
    const button = document.getElementById('forgery-create');
    if (button) { button.disabled = true; button.textContent = 'Generating…'; }
    const response = await api.createInteractiveForgery(forgerySessionId);
    if (!response.ok) { alert(response.error || 'Could not create forged signature.'); renderForgeryWizard(); return; }
    forgeryCreation = response.data.result;
    forgeryState.forged = true;
    renderForgeryWizard();
  }

  async function submitForgery() {
    const button = document.getElementById('forgery-submit');
    if (button) { button.disabled = true; button.textContent = 'Submitting…'; }
    const response = await api.submitInteractiveForgery(forgerySessionId);
    if (!response.ok) { alert(response.error || 'Could not submit forged signature.'); renderForgeryWizard(); return; }
    forgerySubmitExplanation = response.data.result.explanation;
    forgeryState.submitted = true;
    renderForgeryWizard();
  }

  async function verifyForgery() {
    const button = document.getElementById('forgery-verify');
    if (button) { button.disabled = true; button.textContent = 'Checking…'; }
    const response = await api.verifyInteractiveForgery(forgerySessionId);
    if (!response.ok) { alert(response.error || 'Signature verification failed.'); renderForgeryWizard(); return; }
    forgeryVerification = response.data.result;
    forgeryState.verified = true;
    renderForgeryWizard();
  }

  async function completeForgery() {
    const button = document.getElementById('forgery-complete');
    if (button) { button.disabled = true; button.textContent = 'Generating…'; }
    const response = await api.completeInteractiveForgery(forgerySessionId);
    if (!response.ok) { alert(response.error || 'Could not create evidence report.'); renderForgeryWizard(); return; }
    forgeryReport = response.data.result;
    forgeryState.completed = true;
    renderForgeryWizard();
  }

  function resetForgery() {
    forgerySessionId = null;
    forgeryOriginal = null;
    forgeryCreation = null;
    forgeryVerification = null;
    forgeryReport = null;
    forgerySubmitExplanation = 'The forged signature was submitted. Verification has not run yet.';
    Object.keys(forgeryState).forEach(key => { forgeryState[key] = false; });
    forgeryCollapsedAll = false;
    renderForgeryWizard();
  }

  document.addEventListener('click', event => {
    const target = event.target && event.target.closest ? event.target.closest('button') : event.target;
    const id = target && target.id;
    if (id === 'forgery-prepare') prepareForgery();
    if (id === 'forgery-create') createForgery();
    if (id === 'forgery-submit') submitForgery();
    if (id === 'forgery-verify') verifyForgery();
    if (id === 'forgery-complete') completeForgery();
    if (id === 'forgery-reset') resetForgery();
    if (id === 'forgery-toggle-all') {
      forgeryCollapsedAll = !forgeryCollapsedAll;
      renderForgeryWizard();
    }
  });

  renderForgeryWizard();

  document.addEventListener('click', event => {
    const button = event.target && event.target.closest ? event.target.closest('[data-global-window-toggle]') : null;
    if (!button) return;
    const id = button.dataset.globalWindowToggle;
    collapsedDemoWindows[id] = !collapsedDemoWindows[id];
    const container = document.getElementById('result-' + id);
    const content = container && container.querySelector('.demo-global-window-content');
    if (content) content.classList.toggle('is-collapsed', collapsedDemoWindows[id]);
    button.setAttribute('aria-label', collapsedDemoWindows[id] ? 'Expand window' : 'Collapse window');
    button.title = collapsedDemoWindows[id] ? 'Expand' : 'Collapse';
    button.querySelector('span').textContent = collapsedDemoWindows[id] ? '⌄' : '⌃';
  });

  async function runMessageAttack(id) {
    const button = document.getElementById('attack-' + id);
    const output = document.getElementById('result-' + id);
    if (!button || !output) return;

    button.disabled = true;
    button.textContent = 'Running simulation…';
    output.innerHTML = '<p class="hint">Preparing isolated sample data and running verification checks…</p>';

    try {
      const response = await api.runDemoAttack(id);
      if (!response || !response.ok) {
        output.innerHTML = `<p class="error-text">${esc(response && response.error ? response.error : 'Simulation failed.')}</p>`;
        return;
      }
      const result = response.data && response.data.result;
      if (!result || !Array.isArray(result.verification_steps)) {
        output.innerHTML = '<p class="error-text">The server returned an incomplete demo result. Check the backend update.</p>';
        return;
      }
      renderAttackResult(id, result);
    } catch (error) {
      console.error('Attack demo failed:', error);
      output.innerHTML = '<p class="error-text">Unable to run this simulation. Check the server logs and try again.</p>';
    } finally {
      button.disabled = false;
      button.textContent = 'Run Simulation Again';
    }
  }


  attackIds.filter((id) => !['tampering', 'forged_signature', 'replay', 'expired', 'revoked_key'].includes(id)).forEach((id) => {
    const button = document.getElementById('attack-' + id);
    if (button) button.addEventListener('click', () => runMessageAttack(id));
  });

})();
