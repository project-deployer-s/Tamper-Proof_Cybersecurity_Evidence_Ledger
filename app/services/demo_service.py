from app.services.ledger_service import calculate_entry_hash, GENESIS_HASH
from datetime import datetime, timedelta, timezone

from security.ecdsa import generate_key_pair, sign_data
from security.canonical import create_canonical_payload
from security.hashing import calculate_sha256
from security.verification import verify_message


ATTACKS = {
    "tampering": {
        "name": "Message Tampering",
        "description": "The message content was modified after signing.",
        "expected": "TAMPERED"
    },
    "forged_signature": {
        "name": "Forged Signature",
        "description": "The message was signed using an unauthorized private key.",
        "expected": "INVALID_SIGNATURE"
    },
    "replay": {
        "name": "Replay Attack",
        "description": "A previously used nonce was submitted again.",
        "expected": "REPLAY"
    },
    "expired": {
        "name": "Expired Message",
        "description": "The message timestamp is outside the allowed time window.",
        "expected": "EXPIRED"
    },
    "revoked_key": {
        "name": "Revoked Key Attack",
        "description": "The signing key has been revoked.",
        "expected": "REVOKED_KEY"
    }
}


def simulate_attack(attack_type):
    if attack_type not in ATTACKS:
        return None, "Unknown attack type"

    now = datetime.now(timezone.utc)

    sender = "demo_sender"
    receiver = "demo_receiver"
    nonce = "demo-" + attack_type

    message = "Transfer approved for demonstration."

    timestamp_datetime = now
    timestamp = now.isoformat()

    private_key, public_key = generate_key_pair()

    original_payload = create_canonical_payload(
        sender, receiver, timestamp, nonce, message
    )

    content_hash = calculate_sha256(original_payload)

    signing_key = private_key

    if attack_type == "tampering":
        # Keep the original hash and signature,
        # but modify the message.
        message = "Unauthorized transfer of funds."

    elif attack_type == "forged_signature":
        # Sign with an unrelated private key.
        attacker_private_key, _ = generate_key_pair()
        signing_key = attacker_private_key

    elif attack_type == "replay":
        # Simulate a nonce that was already used.
        used_nonces = {nonce}

    elif attack_type == "expired":
        timestamp_datetime = now - timedelta(hours=1)
        timestamp = timestamp_datetime.isoformat()

        original_payload = create_canonical_payload(
            sender, receiver, timestamp, nonce, message
        )

        content_hash = calculate_sha256(original_payload)

    elif attack_type == "revoked_key":
        pass

    if attack_type != "forged_signature":
        signature = sign_data(
            signing_key,
            original_payload
        )
    else:
        signature = sign_data(
            signing_key,
            original_payload
        )

    if attack_type != "replay":
        used_nonces = set()

    verdict = verify_message(
        public_key=public_key,
        signature=signature,
        sender=sender,
        receiver=receiver,
        timestamp=timestamp,
        timestamp_datetime=timestamp_datetime,
        nonce=nonce,
        message=message,
        expected_content_hash=content_hash,
        sender_known=True,
        used_nonces=used_nonces,
        max_age_seconds=300,
        now=now,
        key_revoked=(attack_type == "revoked_key")
    )

    expected = ATTACKS[attack_type]["expected"]

    return {
        "attack": attack_type,
        "name": ATTACKS[attack_type]["name"],
        "description": ATTACKS[attack_type]["description"],
        "expected_verdict": expected,
        "actual_verdict": verdict.value,
        "detected": verdict.value == expected,
        "message": (
            "Attack successfully detected."
            if verdict.value == expected
            else "Unexpected verification result."
        )
    }, None

def simulate_ledger_tampering():
    """Demonstrate hash-chain and simulated external-anchor protection."""

    import copy

    timestamp = datetime.now(timezone.utc).isoformat()

    entries = [
        {
            "seq": 1,
            "event_type": "SENT",
            "message_id": 101,
            "actor_id": 1,
            "detail": {"sender": "alice", "receiver": "bob"},
            "prev_hash": GENESIS_HASH,
            "created_at": timestamp
        },
        {
            "seq": 2,
            "event_type": "VERIFIED",
            "message_id": 101,
            "actor_id": 2,
            "detail": {"verdict": "GENUINE"},
            "prev_hash": None,
            "created_at": timestamp
        }
    ]

    entries[0]["entry_hash"] = calculate_entry_hash(entries[0])
    entries[1]["prev_hash"] = entries[0]["entry_hash"]
    entries[1]["entry_hash"] = calculate_entry_hash(entries[1])

    trusted_anchor = entries[-1]["entry_hash"]

    # Scenario A: Modify an entry without recalculating its hash.
    simple_tampering = copy.deepcopy(entries)
    simple_tampering[0]["detail"] = {
        "sender": "alice",
        "receiver": "mallory"
    }

    calculated_hash = calculate_entry_hash({
        key: value
        for key, value in simple_tampering[0].items()
        if key != "entry_hash"
    })

    simple_detected = calculated_hash != simple_tampering[0]["entry_hash"]

    # Scenario B: Modify the entry and recalculate the entire chain.
    advanced_tampering = copy.deepcopy(entries)
    advanced_tampering[0]["detail"] = {
        "sender": "alice",
        "receiver": "mallory"
    }

    advanced_tampering[0]["entry_hash"] = calculate_entry_hash({
        key: value
        for key, value in advanced_tampering[0].items()
        if key != "entry_hash"
    })

    advanced_tampering[1]["prev_hash"] = advanced_tampering[0]["entry_hash"]

    advanced_tampering[1]["entry_hash"] = calculate_entry_hash({
        key: value
        for key, value in advanced_tampering[1].items()
        if key != "entry_hash"
    })

    local_chain_valid = (
        advanced_tampering[1]["prev_hash"]
        == advanced_tampering[0]["entry_hash"]
    )

    anchor_matches = advanced_tampering[-1]["entry_hash"] == trusted_anchor

    return {
        "simple_tampering": {
            "detected": simple_detected,
            "result": "TAMPERED" if simple_detected else "NOT_DETECTED"
        },
        "advanced_tampering": {
            "local_chain_valid": local_chain_valid,
            "external_anchor_matches": anchor_matches,
            "detected": local_chain_valid and not anchor_matches,
            "result": (
                "EXTERNAL_ANCHOR_MISMATCH"
                if local_chain_valid and not anchor_matches
                else "NOT_DETECTED"
            )
        }
    }