
/* Attack Demonstrations - Real Backend */
(async function () {
  'use strict';

  if (!App.requireLogin()) return;

  App.mountNav('demo');

  const attacks = [
    'tampering',
    'forged_signature',
    'replay',
    'expired',
    'revoked_key'
  ];

  function showResult(id, result) {
    const container = document.getElementById('result-' + id);

    const detected = result.detected;
    const verdict = App.esc(result.actual_verdict);

    container.innerHTML = `
      <div class="seal ${detected ? 'ok' : 'bad'}" role="status">
        <span class="seal-icon" aria-hidden="true">
          ${detected ? '✓' : '✕'}
        </span>
        <div>
          <div class="seal-title">
            ${detected ? 'Attack Detected' : 'Detection Failed'}
          </div>
          <p>${App.esc(result.message)}</p>
        </div>
      </div>

      <div class="panel" style="margin-top:12px">
        <p><strong>Attack:</strong> ${App.esc(result.name)}</p>
        <p><strong>Expected verdict:</strong>
          ${App.esc(result.expected_verdict)}
        </p>
        <p><strong>Actual verdict:</strong>
          <span class="mono">${verdict}</span>
        </p>
        <p><strong>Description:</strong>
          ${App.esc(result.description)}
        </p>
      </div>
    `;
  }

  async function runAttack(id) {
    const button = document.getElementById('attack-' + id);
    const output = document.getElementById('result-' + id);

    button.disabled = true;
    button.textContent = 'Running simulation...';

    output.innerHTML =
      '<p class="hint">Executing cryptographic verification...</p>';

    try {
      const response = await api.runDemoAttack(id);

      if (!response.ok) {
        output.innerHTML =
          '<p class="error-text">' +
          App.esc(response.error || 'Simulation failed.') +
          '</p>';
        return;
      }

      const result = response.data.result;

      if (!result) {
        output.innerHTML =
          '<p class="error-text">Invalid simulation response.</p>';
        return;
      }

      showResult(id, result);

    } catch (error) {
      output.innerHTML =
        '<p class="error-text">Unable to run simulation.</p>';
    } finally {
      button.disabled = false;
      button.textContent = 'Run Simulation Again';
    }
  }

  attacks.forEach((id) => {
    const button = document.getElementById('attack-' + id);

    if (button) {
      button.addEventListener('click', () => runAttack(id));
    }
  });

    // Ledger tampering simulation
  const ledgerButton = document.getElementById(
    'attack-ledger-tampering'
  );

  ledgerButton.addEventListener('click', async () => {
    const output = document.getElementById(
      'result-ledger-tampering'
    );

    ledgerButton.disabled = true;
    ledgerButton.textContent = 'Running simulation...';

    output.innerHTML =
      '<p class="hint">Simulating ledger modification...</p>';

    try {
      const response = await api.runLedgerTamperingDemo();

      if (!response.ok) {
        output.innerHTML =
          '<p class="error-text">' +
          App.esc(response.error) +
          '</p>';
        return;
      }

      const result = response.data.result;
      const simple = result.simple_tampering;
      const advanced = result.advanced_tampering;

      output.innerHTML = `
        <div class="seal ok">
          <span class="seal-icon">✓</span>
          <div>
            <div class="seal-title">Ledger Tampering Detected</div>
            <p>Both tampering scenarios were evaluated.</p>
          </div>
        </div>

        <div class="panel" style="margin-top:12px">
          <h3>Scenario A: Direct modification</h3>
          <p>Detection: <strong>${simple.detected ? 'Passed' : 'Failed'}</strong></p>
          <p>Result: <strong>${App.esc(simple.result)}</strong></p>

          <h3>Scenario B: Rewritten hash chain</h3>
          <p>Local chain valid:
            <strong>${advanced.local_chain_valid ? 'Yes' : 'No'}</strong>
          </p>
          <p>External anchor matches:
            <strong>${advanced.external_anchor_matches ? 'Yes' : 'No'}</strong>
          </p>
          <p>Detection:
            <strong>${advanced.detected ? 'Passed' : 'Failed'}</strong>
          </p>
          <p>Result: <strong>${App.esc(advanced.result)}</strong></p>
        </div>
      `;

    } catch (error) {
      output.innerHTML =
        '<p class="error-text">Unable to run simulation.</p>';
    } finally {
      ledgerButton.disabled = false;
      ledgerButton.textContent = 'Run Simulation Again';
    }
  });
})();
