import pytest
from app.services.demo_service import simulate_attack, simulate_ledger_tampering


@pytest.mark.parametrize("attack,verdict", [
    ("tampering", "TAMPERED"),
    ("forged_signature", "INVALID_SIGNATURE"),
    ("replay", "REPLAY"),
    ("expired", "EXPIRED"),
    ("revoked_key", "REVOKED_KEY"),
])
def test_attack_demo_returns_explanatory_result(attack, verdict):
    result, error = simulate_attack(attack)
    assert error is None
    assert result["actual_verdict"] == verdict
    assert result["expected_verdict"] == verdict
    assert result["detected"] is True
    assert result["simulation_type"] == "isolated_in_memory"
    assert result["verification_steps"]
    assert result["attacker"]["action"]
    assert result["evidence"]["recorded"] is False
    assert result["safety"]["modifies_production_ledger"] is False


def test_tampering_exposes_changed_message_and_hash_mismatch():
    result, _ = simulate_attack("tampering")
    assert result["scenario"]["original_message"] != result["scenario"]["submitted_message"]
    assert result["integrity"]["content_hash_matches"] is False
    assert result["verification_steps"][4]["status"] == "failed"


def test_forgery_exposes_signature_failure():
    result, _ = simulate_attack("forged_signature")
    assert result["attacker"]["used_unrelated_signing_key"] is True
    assert result["integrity"]["content_hash_matches"] is True
    assert result["integrity"]["signature_valid_for_sender"] is False
    assert result["verification_steps"][5]["status"] == "failed"


def test_replay_exposes_nonce_reuse():
    result, _ = simulate_attack("replay")
    assert result["attacker"]["reused_nonce"] is True
    assert result["verification_steps"][2]["status"] == "failed"


def test_expired_demo_explains_freshness_window():
    result, _ = simulate_attack("expired")
    assert result["scenario"]["freshness_window_seconds"] == 300
    assert result["verification_steps"][3]["status"] == "failed"


def test_revoked_key_exposes_key_status_check():
    result, _ = simulate_attack("revoked_key")
    assert result["attacker"]["used_revoked_key"] is True
    assert result["verification_steps"][1]["status"] == "failed"


def test_unknown_attack_is_rejected():
    result, error = simulate_attack("unknown")
    assert result is None
    assert error == "Unknown attack type"


def test_ledger_demo_is_disposable_and_explains_both_tampering_cases():
    result = simulate_ledger_tampering()
    assert result["permanent_ledger_modified"] is False
    assert result["trusted_anchor_type"] == "simulated_snapshot"
    assert result["simple_tampering"]["detected"] is True
    assert result["advanced_tampering"]["local_chain_valid"] is True
    assert result["advanced_tampering"]["external_anchor_matches"] is False
    assert result["advanced_tampering"]["detected"] is True
