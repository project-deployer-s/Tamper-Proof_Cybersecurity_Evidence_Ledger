"""Safe, isolated attack demonstrations using generated in-memory data."""
from datetime import datetime, timedelta, timezone

from app.services.ledger_service import calculate_entry_hash, GENESIS_HASH
from security.ecdsa import generate_key_pair, sign_data, verify_signature
from security.canonical import create_canonical_payload
from security.hashing import calculate_sha256
from security.verification import verify_message

DEMO_MAX_AGE_SECONDS = 300

ATTACKS = {
    "tampering": {"name": "Message Tampering", "description": "An attacker changes the message after it has been digitally signed.", "expected": "TAMPERED", "category": "message_integrity", "difficulty": "Beginner"},
    "forged_signature": {"name": "Forged Signature", "description": "An attacker signs a message with a different private key that does not belong to the claimed sender.", "expected": "INVALID_SIGNATURE", "category": "digital_signature", "difficulty": "Intermediate"},
    "replay": {"name": "Replay Attack", "description": "An attacker resubmits a previously accepted message using the same nonce.", "expected": "REPLAY", "category": "replay_protection", "difficulty": "Intermediate"},
    "expired": {"name": "Stale Message Attack", "description": "An attacker resubmits a message whose timestamp is outside the 5-minute verification freshness window.", "expected": "EXPIRED", "category": "freshness", "difficulty": "Beginner"},
    "revoked_key": {"name": "Revoked Key Attack", "description": "An attacker attempts to authenticate with a signing key that has been revoked.", "expected": "REVOKED_KEY", "category": "key_management", "difficulty": "Intermediate"},
}


def _step(title, status, explanation):
    return {"title": title, "status": status, "explanation": explanation}


def _verification_timeline(key_revoked, nonce_reused, timestamp_fresh,
                           content_hash_matches, signature_valid):
    """Mirror verify_message's check order and its early-exit behavior."""
    checks = [
        ("Sender identity", True, "The demo sender is recognized."),
        ("Signing-key status", not key_revoked, "The signing key is revoked." if key_revoked else "The signing key is active."),
        ("Replay protection", not nonce_reused, "This nonce has already been used." if nonce_reused else "This nonce has not been used before."),
        ("Timestamp freshness", timestamp_fresh, "Timestamp is within the 5-minute verification window." if timestamp_fresh else "Timestamp is older than the 5-minute verification window."),
        ("Content integrity", content_hash_matches, "Calculated content hash matches the signed hash." if content_hash_matches else "Calculated content hash differs from the signed hash."),
        ("Digital signature", signature_valid, "Signature matches the sender's public key." if signature_valid else "Signature does not match the sender's public key."),
    ]
    timeline, failed = [], False
    for title, passed, explanation in checks:
        if failed:
            timeline.append(_step(title, "not_reached", "Not checked because an earlier security check rejected the message."))
        elif passed:
            timeline.append(_step(title, "passed", explanation))
        else:
            timeline.append(_step(title, "failed", explanation))
            failed = True
    return timeline


def simulate_attack(attack_type):
    """Run a scenario against fresh keys and data; never touch production data."""
    if attack_type not in ATTACKS:
        return None, "Unknown attack type"

    now = datetime.now(timezone.utc)
    sender, receiver = "demo_sender", "demo_receiver"
    nonce = "demo-" + attack_type
    original_message = "Transfer approved for demonstration."
    submitted_message = original_message
    timestamp_datetime, timestamp = now, now.isoformat()
    sender_private_key, sender_public_key = generate_key_pair()
    signing_key = sender_private_key
    key_revoked = attack_type == "revoked_key"
    nonce_reused = attack_type == "replay"

    original_payload = create_canonical_payload(sender, receiver, timestamp, nonce, original_message)
    original_hash = calculate_sha256(original_payload)
    attacker_action, modified_message = "", None

    if attack_type == "tampering":
        submitted_message = "Unauthorized transfer of funds."
        modified_message = submitted_message
        attacker_action = "Changed the message body but kept the original signature and content hash."
    elif attack_type == "forged_signature":
        signing_key, _ = generate_key_pair()
        attacker_action = "Generated an unrelated key pair and signed the claimed sender's message with the attacker's private key."
    elif attack_type == "replay":
        attacker_action = "Resubmitted a previously accepted message with its already-used nonce."
    elif attack_type == "expired":
        timestamp_datetime = now - timedelta(hours=1)
        timestamp = timestamp_datetime.isoformat()
        original_payload = create_canonical_payload(sender, receiver, timestamp, nonce, original_message)
        original_hash = calculate_sha256(original_payload)
        attacker_action = "Resubmitted a one-hour-old message; the allowed verification freshness window is 5 minutes."
    elif attack_type == "revoked_key":
        attacker_action = "Attempted to authenticate with a key marked as revoked."

    signature = sign_data(signing_key, original_payload)
    used_nonces = {nonce} if nonce_reused else set()
    submitted_payload = create_canonical_payload(sender, receiver, timestamp, nonce, submitted_message)
    submitted_hash = calculate_sha256(submitted_payload)
    hash_matches = submitted_hash == original_hash
    signature_valid = verify_signature(sender_public_key, submitted_payload, signature)
    timestamp_fresh = (timestamp_datetime <= now and now - timestamp_datetime <= timedelta(seconds=DEMO_MAX_AGE_SECONDS))

    verdict = verify_message(
        public_key=sender_public_key, signature=signature, sender=sender,
        receiver=receiver, timestamp=timestamp, timestamp_datetime=timestamp_datetime,
        nonce=nonce, message=submitted_message, expected_content_hash=original_hash,
        sender_known=True, used_nonces=used_nonces, max_age_seconds=DEMO_MAX_AGE_SECONDS,
        now=now, key_revoked=key_revoked,
    )
    expected = ATTACKS[attack_type]["expected"]
    detected = verdict.value == expected

    result = {
        # Legacy fields retained for existing frontend compatibility.
        "attack": attack_type,
        "name": ATTACKS[attack_type]["name"],
        "description": ATTACKS[attack_type]["description"],
        "expected_verdict": expected,
        "actual_verdict": verdict.value,
        "detected": detected,
        "message": "Attack successfully detected." if detected else "The simulation returned an unexpected verification result.",
        # Structured explanation data for the upgraded demo UI.
        "simulation_type": "isolated_in_memory",
        "scenario": {
            "sender": sender, "receiver": receiver,
            "original_message": original_message,
            "submitted_message": submitted_message,
            "timestamp": timestamp, "nonce": nonce,
            "freshness_window_seconds": DEMO_MAX_AGE_SECONDS,
        },
        "attacker": {
            "action": attacker_action, "modified_message": modified_message,
            "used_unrelated_signing_key": attack_type == "forged_signature",
            "reused_nonce": nonce_reused, "used_revoked_key": key_revoked,
        },
        "integrity": {
            "original_content_hash": original_hash,
            "submitted_content_hash": submitted_hash,
            "content_hash_matches": hash_matches,
            "signature_valid_for_sender": signature_valid,
        },
        "verification_steps": _verification_timeline(
            key_revoked, nonce_reused, timestamp_fresh, hash_matches, signature_valid
        ),
        "explanation": (
            f"The verifier returned {verdict.value}. {ATTACKS[attack_type]['description']} "
            + ("The attempted attack was detected as expected." if detected else "The expected detection did not occur; investigate the verification logic.")
        ),
        "evidence": {
            "evidence_id": f"DEMO-{attack_type.upper()}-{now.strftime('%Y%m%d%H%M%S%f')}",
            "recorded": False, "storage": "temporary_demo_result",
            "note": "Generated in memory for demonstration only; this is not a permanent ledger entry.",
        },
        "safety": {
            "is_simulation": True, "uses_real_user_data": False,
            "modifies_production_ledger": False, "private_keys_exposed": False,
        },
    }
    return result, None


def simulate_ledger_tampering():
    """Demonstrate tampering against disposable entries and a simulated snapshot."""
    import copy
    timestamp = datetime.now(timezone.utc).isoformat()
    entries = [
        {"seq": 1, "event_type": "SENT", "message_id": 101, "actor_id": 1,
         "detail": {"sender": "alice", "receiver": "bob"}, "prev_hash": GENESIS_HASH,
         "created_at": timestamp},
        {"seq": 2, "event_type": "VERIFIED", "message_id": 101, "actor_id": 2,
         "detail": {"verdict": "GENUINE"}, "prev_hash": None, "created_at": timestamp},
    ]
    entries[0]["entry_hash"] = calculate_entry_hash(entries[0])
    entries[1]["prev_hash"] = entries[0]["entry_hash"]
    entries[1]["entry_hash"] = calculate_entry_hash(entries[1])
    trusted_anchor = entries[-1]["entry_hash"]

    simple = copy.deepcopy(entries)
    simple[0]["detail"] = {"sender": "alice", "receiver": "mallory"}
    recalculated = calculate_entry_hash({k: v for k, v in simple[0].items() if k != "entry_hash"})
    simple_detected = recalculated != simple[0]["entry_hash"]

    advanced = copy.deepcopy(entries)
    advanced[0]["detail"] = {"sender": "alice", "receiver": "mallory"}
    advanced[0]["entry_hash"] = calculate_entry_hash({k: v for k, v in advanced[0].items() if k != "entry_hash"})
    advanced[1]["prev_hash"] = advanced[0]["entry_hash"]
    advanced[1]["entry_hash"] = calculate_entry_hash({k: v for k, v in advanced[1].items() if k != "entry_hash"})
    local_chain_valid = advanced[1]["prev_hash"] == advanced[0]["entry_hash"]
    anchor_matches = advanced[-1]["entry_hash"] == trusted_anchor

    return {
        "simulation_type": "disposable_in_memory_ledger",
        "permanent_ledger_modified": False,
        "trusted_anchor_type": "simulated_snapshot",
        "simple_tampering": {
            "original_entry": entries[0], "modified_entry": simple[0],
            "stored_hash": simple[0]["entry_hash"], "recalculated_hash": recalculated,
            "detected": simple_detected, "result": "TAMPERED" if simple_detected else "NOT_DETECTED",
            "explanation": "The entry content changed, but its stored hash was not updated.",
        },
        "advanced_tampering": {
            "local_chain_valid": local_chain_valid, "external_anchor_matches": anchor_matches,
            "trusted_anchor": trusted_anchor, "modified_chain_head": advanced[-1]["entry_hash"],
            "detected": local_chain_valid and not anchor_matches,
            "result": "EXTERNAL_ANCHOR_MISMATCH" if local_chain_valid and not anchor_matches else "NOT_DETECTED",
            "explanation": "The attacker recalculated the local chain, so its internal links are valid, but the final hash no longer matches the previously trusted snapshot.",
        },
    }
