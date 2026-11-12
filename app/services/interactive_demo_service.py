from datetime import datetime, timezone
from security.ecdsa import generate_key_pair, sign_data, verify_signature
from security.canonical import create_canonical_payload
from security.hashing import calculate_sha256
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Interactive Message Tampering Lab
# ---------------------------------------------------------------------------
# These sessions are deliberately in-memory and isolated from application
# messages, user keys, nonce storage, and the permanent evidence ledger.

import hashlib
import threading
import uuid

_INTERACTIVE_DEMO_SESSIONS = {}
_INTERACTIVE_DEMO_LOCK = threading.Lock()
_INTERACTIVE_DEMO_TTL_SECONDS = 1800
_INTERACTIVE_DEMO_ORIGINAL = "Transfer approved for demonstration."


def _interactive_session(session_id):
    """Return an active session, removing expired sessions opportunistically."""
    now = datetime.now(timezone.utc)
    with _INTERACTIVE_DEMO_LOCK:
        expired = [
            key for key, value in _INTERACTIVE_DEMO_SESSIONS.items()
            if (now - value["created_at"]).total_seconds() > _INTERACTIVE_DEMO_TTL_SECONDS
        ]
        for key in expired:
            _INTERACTIVE_DEMO_SESSIONS.pop(key, None)
        return _INTERACTIVE_DEMO_SESSIONS.get(session_id)


def prepare_interactive_tampering():
    """Create and sign an original sample message; no attack has happened yet."""
    now = datetime.now(timezone.utc)
    sender = "alice.demo"
    receiver = "rahul.demo"
    nonce = "interactive-" + uuid.uuid4().hex
    timestamp = now.isoformat()
    original_message = _INTERACTIVE_DEMO_ORIGINAL

    private_key, public_key = generate_key_pair()
    original_payload = create_canonical_payload(
        sender, receiver, timestamp, nonce, original_message
    )
    original_hash = calculate_sha256(original_payload)
    signature = sign_data(private_key, original_payload)

    session_id = uuid.uuid4().hex
    session = {
        "created_at": now,
        "sender": sender,
        "receiver": receiver,
        "nonce": nonce,
        "timestamp": timestamp,
        "original_message": original_message,
        "original_payload": original_payload,
        "original_hash": original_hash,
        "private_key": private_key,
        "public_key": public_key,
        "signature": signature,
        "submitted_message": None,
        "submitted_payload": None,
        "submitted_hash": None,
        "hash_check": None,
        "signature_check": None,
        "stage": "prepared",
    }
    with _INTERACTIVE_DEMO_LOCK:
        _INTERACTIVE_DEMO_SESSIONS[session_id] = session

    return {
        "session_id": session_id,
        "stage": "prepared",
        "sender": sender,
        "receiver": receiver,
        "timestamp": timestamp,
        "nonce": nonce,
        "original_message": original_message,
        "original_content_hash": original_hash,
        "signature_fingerprint": calculate_sha256(signature),
        "signature_created": True,
        "explanation": (
            "Alice's sample message has been converted into canonical data, "
            "hashed with SHA-256, and signed with a newly generated demo-only ECDSA key."
        ),
        "safety": {
            "simulation": True,
            "real_user_data": False,
            "production_ledger_modified": False,
            "session_storage": "temporary_server_memory",
        },
    }


def tamper_interactive_message(session_id, modified_message):
    """Accept the learner's manual edit without running verification yet."""
    session = _interactive_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "prepared":
        return None, "The message can only be modified after preparation and before submission."
    if not isinstance(modified_message, str) or not modified_message.strip():
        return None, "Enter a non-empty modified message."
    if modified_message == session["original_message"]:
        return None, "Change the message before submitting the tampering attempt."
    if len(modified_message) > 2000:
        return None, "The demo message must be 2,000 characters or fewer."

    submitted_payload = create_canonical_payload(
        session["sender"], session["receiver"], session["timestamp"],
        session["nonce"], modified_message
    )
    session["submitted_message"] = modified_message
    session["submitted_payload"] = submitted_payload
    session["submitted_hash"] = calculate_sha256(submitted_payload)
    session["stage"] = "submitted"

    return {
        "stage": "submitted",
        "original_message": session["original_message"],
        "submitted_message": modified_message,
        "original_content_hash": session["original_hash"],
        "submitted_content_hash": session["submitted_hash"],
        "hashes_calculated": True,
        "verification_started": False,
        "explanation": (
            "The edited message has been submitted. The original signature has not "
            "been changed. No security check has run yet; choose the next check manually."
        ),
    }, None


def run_interactive_tampering_check(session_id, check_name):
    """Run exactly one requested verification check after manual submission."""
    session = _interactive_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] not in ("submitted", "hash_checked"):
        return None, "Submit a modified message before running verification checks."

    if check_name == "hash":
        if session["hash_check"] is not None:
            return None, "The content-hash check has already been run."
        matches = session["submitted_hash"] == session["original_hash"]
        session["hash_check"] = {
            "passed": matches,
            "status": "passed" if matches else "failed",
            "original_hash": session["original_hash"],
            "submitted_hash": session["submitted_hash"],
            "explanation": (
                "The submitted content hash matches the signed hash."
                if matches else
                "The hashes do not match. The message content changed after signing."
            ),
        }
        session["stage"] = "hash_checked"
        return {
            "stage": session["stage"],
            "check": "hash",
            **session["hash_check"],
        }, None

    if check_name == "signature":
        if session["signature_check"] is not None:
            return None, "The signature check has already been run."
        valid = verify_signature(
            session["public_key"],
            session["submitted_payload"],
            session["signature"],
        )
        session["signature_check"] = {
            "passed": valid,
            "status": "passed" if valid else "failed",
            "signature_fingerprint": calculate_sha256(session["signature"]),
            "explanation": (
                "The signature is valid for the submitted content."
                if valid else
                "The original signature cannot authenticate the edited content. "
                "It was created for the original message, not this modified message."
            ),
        }
        return {
            "stage": session["stage"],
            "check": "signature",
            **session["signature_check"],
        }, None

    return None, "Unknown verification check. Use 'hash' or 'signature'."


def complete_interactive_tampering(session_id):
    """Build a final report only after the learner has run both checks."""
    session = _interactive_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["hash_check"] is None or session["signature_check"] is None:
        return None, "Run both the content-hash and digital-signature checks first."
    if session["stage"] == "completed":
        return None, "This demonstration has already been completed."

    now = datetime.now(timezone.utc)
    detected = not session["hash_check"]["passed"] and not session["signature_check"]["passed"]
    evidence_id = f"DEMO-TAMPERING-{now.strftime('%Y%m%d%H%M%S%f')}"
    session["stage"] = "completed"

    return {
        "stage": "completed",
        "detected": detected,
        "verdict": "TAMPERED" if detected else "NOT_TAMPERED",
        "evidence": {
            "evidence_id": evidence_id,
            "recorded": False,
            "storage": "temporary_demo_result",
            "note": "This is a temporary demonstration report, not a permanent ledger entry.",
        },
        "checks": {
            "content_hash": session["hash_check"],
            "digital_signature": session["signature_check"],
        },
        "explanation": (
            "The system detected the manual message modification: its content hash "
            "changed and the original digital signature does not validate the edited content."
            if detected else
            "The checks did not produce the expected tampering result. Review the submitted content."
        ),
        "safety": {
            "simulation": True,
            "real_user_data": False,
            "production_ledger_modified": False,
            "private_key_exposed": False,
        },
    }, None


# ---------------------------------------------------------------------------
# Interactive Forged Digital Signature Lab
# ---------------------------------------------------------------------------
# All keys and signatures below are generated for this temporary demo only.
_FORGED_SIGNATURE_SESSIONS = {}
_FORGED_SIGNATURE_LOCK = threading.Lock()


def _forged_signature_session(session_id):
    now = datetime.now(timezone.utc)
    with _FORGED_SIGNATURE_LOCK:
        expired = [
            key for key, value in _FORGED_SIGNATURE_SESSIONS.items()
            if (now - value["created_at"]).total_seconds() > _INTERACTIVE_DEMO_TTL_SECONDS
        ]
        for key in expired:
            _FORGED_SIGNATURE_SESSIONS.pop(key, None)
        return _FORGED_SIGNATURE_SESSIONS.get(session_id)


def prepare_interactive_forgery():
    """Create a legitimate sample message signed by Alice's demo-only key."""
    now = datetime.now(timezone.utc)
    sender, receiver = "alice.demo", "rahul.demo"
    nonce = "forgery-" + uuid.uuid4().hex
    timestamp = now.isoformat()
    message = "Transfer ₹500 to Rahul for the project."
    payload = create_canonical_payload(sender, receiver, timestamp, nonce, message)
    legitimate_private, legitimate_public = generate_key_pair()
    legitimate_signature = sign_data(legitimate_private, payload)
    session_id = uuid.uuid4().hex

    _FORGED_SIGNATURE_SESSIONS[session_id] = {
        "created_at": now,
        "sender": sender,
        "receiver": receiver,
        "timestamp": timestamp,
        "nonce": nonce,
        "message": message,
        "payload": payload,
        "legitimate_public": legitimate_public,
        "legitimate_signature": legitimate_signature,
        "attacker_public": None,
        "forged_signature": None,
        "submitted": False,
        "verification": None,
        "stage": "prepared",
    }

    return {
        "session_id": session_id,
        "sender": sender,
        "receiver": receiver,
        "timestamp": timestamp,
        "nonce": nonce,
        "message": message,
        "signature_fingerprint": calculate_sha256(legitimate_signature),
        "explanation": (
            "Alice's message has been signed with her own temporary ECDSA key. "
            "The public key represents the identity the receiver expects."
        ),
        "safety": {
            "simulation": True,
            "real_user_data": False,
            "production_ledger_modified": False,
        },
    }


def create_interactive_forged_signature(session_id):
    """Generate a signature over the same message using an unrelated demo key."""
    session = _forged_signature_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "prepared":
        return None, "A forged signature can only be created once after preparation."

    attacker_private, attacker_public = generate_key_pair()
    forged_signature = sign_data(attacker_private, session["payload"])
    session["attacker_public"] = attacker_public
    session["forged_signature"] = forged_signature
    session["stage"] = "forged"

    from cryptography.hazmat.primitives import serialization
    attacker_public_bytes = attacker_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "stage": "forged",
        "signature_fingerprint": calculate_sha256(forged_signature),
        "attacker_key_fingerprint": calculate_sha256(attacker_public_bytes),
        "explanation": (
            "The attacker generated a new key pair and signed the same message "
            "with the attacker's private key. The signature is mathematically valid "
            "for the attacker's public key, but that key does not belong to Alice."
        ),
        "verification_started": False,
    }, None


def submit_interactive_forged_signature(session_id):
    """Manually submit the attacker's signature for identity verification."""
    session = _forged_signature_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "forged":
        return None, "Generate the forged signature before submitting it."
    session["submitted"] = True
    session["stage"] = "submitted"
    return {
        "stage": "submitted",
        "submitted": True,
        "explanation": (
            "The forged signature has been submitted with the message while claiming "
            "to represent Alice. No verification has run yet."
        ),
    }, None


def verify_interactive_forged_signature(session_id):
    """Run the requested identity check against Alice's trusted public key."""
    session = _forged_signature_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "submitted":
        return None, "Submit the forged signature before running verification."
    if session["verification"] is not None:
        return None, "The signature verification has already been run."

    valid_for_sender = verify_signature(
        session["legitimate_public"], session["payload"], session["forged_signature"]
    )
    valid_for_attacker = verify_signature(
        session["attacker_public"], session["payload"], session["forged_signature"]
    )
    session["verification"] = {
        "valid_for_sender": valid_for_sender,
        "valid_for_attacker": valid_for_attacker,
    }
    session["stage"] = "verified"

    return {
        "stage": "verified",
        "valid_for_sender": valid_for_sender,
        "valid_for_attacker": valid_for_attacker,
        "detected": not valid_for_sender and valid_for_attacker,
        "explanation": (
            "The signature verifies with the attacker's public key but fails with "
            "Alice's trusted public key. This proves the signature was created by "
            "a different key and cannot establish Alice's identity."
            if (not valid_for_sender and valid_for_attacker) else
            "The verification result was unexpected. Review the key identities and signatures."
        ),
    }, None


def complete_interactive_forgery(session_id):
    """Create a temporary evidence report after the manual verification step."""
    session = _forged_signature_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "verified" or session["verification"] is None:
        return None, "Run the signature verification before completing the investigation."

    now = datetime.now(timezone.utc)
    detected = (
        not session["verification"]["valid_for_sender"]
        and session["verification"]["valid_for_attacker"]
    )
    evidence_id = f"DEMO-FORGED-SIGNATURE-{now.strftime('%Y%m%d%H%M%S%f')}"
    session["stage"] = "completed"

    return {
        "stage": "completed",
        "detected": detected,
        "verdict": "FORGED_SIGNATURE_REJECTED" if detected else "UNEXPECTED_RESULT",
        "explanation": (
            "The receiver rejected the forged signature because it did not verify "
            "against Alice's trusted public key, even though it verified against "
            "the attacker's unrelated public key."
            if detected else
            "The expected forgery detection did not occur. Review the verification result."
        ),
        "verification": session["verification"],
        "evidence": {
            "evidence_id": evidence_id,
            "recorded": False,
            "note": "Temporary demonstration evidence only. No permanent ledger entry was created.",
        },
        "safety": {
            "simulation": True,
            "real_user_data": False,
            "production_ledger_modified": False,
            "private_key_exposed": False,
        },
    }, None

# ---------------------------------------------------------------------------
# Interactive Replay Attack Lab
# ---------------------------------------------------------------------------

_REPLAY_SESSIONS = {}
_REPLAY_LOCK = threading.Lock()


def _replay_session(session_id):
    now = datetime.now(timezone.utc)
    with _REPLAY_LOCK:
        expired = [
            key for key, value in _REPLAY_SESSIONS.items()
            if (now - value["created_at"]).total_seconds() > _INTERACTIVE_DEMO_TTL_SECONDS
        ]
        for key in expired:
            _REPLAY_SESSIONS.pop(key, None)
        return _REPLAY_SESSIONS.get(session_id)


def prepare_interactive_replay():
    """Prepare one legitimate signed packet for a controlled replay exercise."""
    now = datetime.now(timezone.utc)
    sender, receiver = "alice.demo", "rahul.demo"
    timestamp = now.isoformat()
    nonce = "replay-" + uuid.uuid4().hex
    message = "Approve the project payment of ₹500."
    private_key, public_key = generate_key_pair()
    payload = create_canonical_payload(sender, receiver, timestamp, nonce, message)
    signature = sign_data(private_key, payload)
    session_id = uuid.uuid4().hex
    _REPLAY_SESSIONS[session_id] = {
        "created_at": now, "sender": sender, "receiver": receiver,
        "timestamp": timestamp, "timestamp_datetime": now, "nonce": nonce,
        "message": message, "payload": payload, "content_hash": calculate_sha256(payload),
        "signature": signature, "public_key": public_key,
        "used_nonces": set(), "first_acceptance": None, "replay_result": None,
        "stage": "prepared",
    }
    return {
        "session_id": session_id, "sender": sender, "receiver": receiver,
        "timestamp": timestamp, "nonce": nonce, "message": message,
        "content_hash": calculate_sha256(payload),
        "signature_fingerprint": calculate_sha256(signature),
        "explanation": "A legitimate packet has been signed with Alice's temporary demo key. It has not yet been received or accepted.",
        "safety": {"simulation": True, "real_user_data": False, "production_ledger_modified": False},
    }


def accept_interactive_replay_original(session_id):
    """Receiver accepts the original packet once and records its nonce."""
    from datetime import timedelta
    from security.verification import verify_message
    session = _replay_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "prepared":
        return None, "The original packet can only be accepted once after preparation."
    verdict = verify_message(
        public_key=session["public_key"], signature=session["signature"],
        sender=session["sender"], receiver=session["receiver"], timestamp=session["timestamp"],
        timestamp_datetime=session["timestamp_datetime"], nonce=session["nonce"],
        message=session["message"], expected_content_hash=session["content_hash"],
        sender_known=True, used_nonces=session["used_nonces"], max_age_seconds=300,
        now=datetime.now(timezone.utc), key_revoked=False,
    )
    if verdict.value != "GENUINE":
        return None, "The original sample packet did not pass verification. Reset and try again."
    session["used_nonces"].add(session["nonce"])
    session["first_acceptance"] = verdict.value
    session["stage"] = "accepted"
    return {"stage": "accepted", "verdict": verdict.value, "nonce_recorded": True,
            "explanation": "The receiver accepted the original signed packet and stored its nonce as used."}, None


def submit_interactive_replay(session_id):
    """Resubmit the exact captured packet; no verification is run in this stage."""
    session = _replay_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "accepted":
        return None, "Accept the original packet before attempting to replay it."
    session["stage"] = "replay_submitted"
    return {"stage": "replay_submitted", "same_message": True, "same_signature": True,
            "same_nonce": True,
            "explanation": "The captured packet has been submitted again without changing its message, signature, timestamp, or nonce. Verification has not run yet."}, None


def verify_interactive_replay(session_id):
    """Verify the replayed packet against the receiver's used-nonce set."""
    from security.verification import verify_message
    session = _replay_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "replay_submitted":
        return None, "Submit the captured packet again before running replay detection."
    verdict = verify_message(
        public_key=session["public_key"], signature=session["signature"],
        sender=session["sender"], receiver=session["receiver"], timestamp=session["timestamp"],
        timestamp_datetime=session["timestamp_datetime"], nonce=session["nonce"],
        message=session["message"], expected_content_hash=session["content_hash"],
        sender_known=True, used_nonces=session["used_nonces"], max_age_seconds=300,
        now=datetime.now(timezone.utc), key_revoked=False,
    )
    session["replay_result"] = verdict.value
    session["stage"] = "verified"
    return {"stage": "verified", "verdict": verdict.value, "detected": verdict.value == "REPLAY",
            "nonce_was_already_used": session["nonce"] in session["used_nonces"],
            "explanation": "Replay protection rejected the packet because its nonce was already recorded during the first successful receipt." if verdict.value == "REPLAY" else "The replay attempt was not rejected as expected. Review nonce tracking."}, None


def complete_interactive_replay(session_id):
    """Produce temporary evidence after replay verification has been run."""
    session = _replay_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "verified":
        return None, "Run replay verification before generating the evidence report."
    now = datetime.now(timezone.utc)
    detected = session["replay_result"] == "REPLAY"
    session["stage"] = "completed"
    return {
        "stage": "completed", "detected": detected,
        "verdict": "REPLAY_ATTACK_REJECTED" if detected else "UNEXPECTED_RESULT",
        "explanation": "The replayed packet was rejected because its nonce had already been consumed by the original accepted message." if detected else "The expected replay rejection did not occur.",
        "evidence": {"evidence_id": f"DEMO-REPLAY-{now.strftime('%Y%m%d%H%M%S%f')}", "recorded": False,
                     "note": "Temporary demonstration evidence only. No permanent ledger entry was created."},
        "safety": {"simulation": True, "real_user_data": False, "production_ledger_modified": False},
    }, None


# ---------------------------------------------------------------------------
# Interactive Expired Digital Signature Lab
# ---------------------------------------------------------------------------
_EXPIRED_SIGNATURE_SESSIONS = {}
_EXPIRED_SIGNATURE_LOCK = threading.Lock()


def _expired_signature_session(session_id):
    now = datetime.now(timezone.utc)
    with _EXPIRED_SIGNATURE_LOCK:
        expired = [
            key for key, value in _EXPIRED_SIGNATURE_SESSIONS.items()
            if (now - value["created_at"]).total_seconds() > _INTERACTIVE_DEMO_TTL_SECONDS
        ]
        for key in expired:
            _EXPIRED_SIGNATURE_SESSIONS.pop(key, None)
        return _EXPIRED_SIGNATURE_SESSIONS.get(session_id)


def prepare_interactive_expired_signature():
    """Create a validly signed sample whose signed timestamp is already expired."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    issued_at = now - timedelta(minutes=10)
    sender, receiver = "alice.demo", "rahul.demo"
    timestamp = issued_at.isoformat()
    nonce = "expired-" + uuid.uuid4().hex
    message = "Approve the project payment of ₹500."
    private_key, public_key = generate_key_pair()
    payload = create_canonical_payload(sender, receiver, timestamp, nonce, message)
    signature = sign_data(private_key, payload)
    session_id = uuid.uuid4().hex
    _EXPIRED_SIGNATURE_SESSIONS[session_id] = {
        "created_at": now, "sender": sender, "receiver": receiver,
        "issued_at": issued_at, "timestamp": timestamp, "nonce": nonce,
        "message": message, "payload": payload, "content_hash": calculate_sha256(payload),
        "signature": signature, "public_key": public_key,
        "stage": "prepared", "verification": None,
    }
    return {
        "session_id": session_id, "sender": sender, "receiver": receiver,
        "timestamp": timestamp, "nonce": nonce, "message": message,
        "content_hash": calculate_sha256(payload),
        "signature_fingerprint": calculate_sha256(signature),
        "validity_window_seconds": 300,
        "age_seconds": int((now - issued_at).total_seconds()),
        "explanation": "This packet was genuinely signed by Alice's temporary demo key, but its signed timestamp is older than the receiver's five-minute freshness window.",
        "safety": {"simulation": True, "real_user_data": False, "production_ledger_modified": False},
    }


def submit_interactive_expired_signature(session_id):
    session = _expired_signature_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "prepared":
        return None, "The expired packet can only be submitted once after preparation."
    session["stage"] = "submitted"
    return {
        "stage": "submitted", "submitted": True,
        "explanation": "The original signed packet has been submitted unchanged. Verification has not run yet.",
    }, None


def verify_interactive_expired_signature(session_id):
    from security.verification import verify_message
    session = _expired_signature_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "submitted":
        return None, "Submit the expired packet before running verification."
    if session["verification"] is not None:
        return None, "Verification has already been run."
    crypto_valid = verify_signature(session["public_key"], session["payload"], session["signature"])
    verdict = verify_message(
        public_key=session["public_key"], signature=session["signature"],
        sender=session["sender"], receiver=session["receiver"],
        timestamp=session["timestamp"], timestamp_datetime=session["issued_at"],
        nonce=session["nonce"], message=session["message"],
        expected_content_hash=session["content_hash"], sender_known=True,
        used_nonces=set(), max_age_seconds=300, now=datetime.now(timezone.utc),
        key_revoked=False,
    )
    session["verification"] = {"cryptographic_signature_valid": crypto_valid, "freshness_verdict": verdict.value}
    session["stage"] = "verified"
    detected = crypto_valid and verdict.value == "EXPIRED"
    return {
        "stage": "verified", "cryptographic_signature_valid": crypto_valid,
        "freshness_verdict": verdict.value, "detected": detected,
        "explanation": (
            "The signature is cryptographically valid, but the packet is rejected because its timestamp is outside the allowed five-minute freshness window."
            if detected else "The expected expired-signature result was not produced. Review the verification output."
        ),
    }, None


def complete_interactive_expired_signature(session_id):
    session = _expired_signature_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "verified":
        return None, "Run signature and freshness verification before generating the evidence report."
    now = datetime.now(timezone.utc)
    detected = session["verification"]["cryptographic_signature_valid"] and session["verification"]["freshness_verdict"] == "EXPIRED"
    session["stage"] = "completed"
    return {
        "stage": "completed", "detected": detected,
        "verdict": "EXPIRED_SIGNATURE_REJECTED" if detected else "UNEXPECTED_RESULT",
        "explanation": "The receiver rejected an authentic but stale signed packet. Cryptographic validity does not override the freshness policy." if detected else "The expired packet was not rejected as expected.",
        "evidence": {"evidence_id": f"DEMO-EXPIRED-{now.strftime('%Y%m%d%H%M%S%f')}", "recorded": False,
                     "note": "Temporary demonstration evidence only. No permanent ledger entry was created."},
        "safety": {"simulation": True, "real_user_data": False, "production_ledger_modified": False},
    }, None


# ---------------------------------------------------------------------------
# Interactive Revoked Digital Key Lab
# ---------------------------------------------------------------------------
_REVOKED_KEY_SESSIONS = {}
_REVOKED_KEY_LOCK = threading.Lock()


def _revoked_key_session(session_id):
    now = datetime.now(timezone.utc)
    with _REVOKED_KEY_LOCK:
        expired = [
            key for key, value in _REVOKED_KEY_SESSIONS.items()
            if (now - value["created_at"]).total_seconds() > _INTERACTIVE_DEMO_TTL_SECONDS
        ]
        for key in expired:
            _REVOKED_KEY_SESSIONS.pop(key, None)
        return _REVOKED_KEY_SESSIONS.get(session_id)


def prepare_interactive_revoked_key():
    """Create a valid signed packet and a disposable trusted-key record."""
    now = datetime.now(timezone.utc)
    sender, receiver = "alice.demo", "rahul.demo"
    timestamp = now.isoformat()
    nonce = "revoked-" + uuid.uuid4().hex
    message = "Approve the project payment of ₹500."
    private_key, public_key = generate_key_pair()
    payload = create_canonical_payload(sender, receiver, timestamp, nonce, message)
    signature = sign_data(private_key, payload)
    session_id = uuid.uuid4().hex
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = calculate_sha256(public_key_bytes)
    _REVOKED_KEY_SESSIONS[session_id] = {
        "created_at": now, "sender": sender, "receiver": receiver,
        "timestamp": timestamp, "timestamp_datetime": now, "nonce": nonce,
        "message": message, "payload": payload, "content_hash": calculate_sha256(payload),
        "signature": signature, "public_key": public_key, "key_fingerprint": fingerprint,
        "key_status": "TRUSTED", "stage": "prepared", "verification": None,
    }
    return {
        "session_id": session_id, "sender": sender, "receiver": receiver,
        "timestamp": timestamp, "nonce": nonce, "message": message,
        "content_hash": calculate_sha256(payload),
        "signature_fingerprint": calculate_sha256(signature),
        "key_fingerprint": fingerprint, "key_status": "TRUSTED",
        "explanation": "Alice's temporary demo key is trusted and has signed this sample packet. The packet has not yet been submitted.",
        "safety": {"simulation": True, "real_user_data": False, "production_keys_modified": False,
                   "production_ledger_modified": False},
    }


def revoke_interactive_demo_key(session_id):
    """Revoke only the disposable key status inside this demo session."""
    session = _revoked_key_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "prepared":
        return None, "The demo key can only be revoked after preparation and before packet submission."
    if session["key_status"] == "REVOKED":
        return None, "The demo key has already been revoked."
    session["key_status"] = "REVOKED"
    session["stage"] = "revoked"
    return {
        "stage": "revoked", "key_status": "REVOKED",
        "key_fingerprint": session["key_fingerprint"],
        "explanation": "The temporary demo key has been revoked in the simulated trust registry. No real user key was changed.",
    }, None


def submit_interactive_revoked_packet(session_id):
    session = _revoked_key_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "revoked":
        return None, "Revoke the demo key before submitting the previously signed packet."
    session["stage"] = "submitted"
    return {
        "stage": "submitted", "submitted": True,
        "explanation": "The original signed packet was submitted unchanged after its signing key had been revoked. Verification has not run yet.",
    }, None


def verify_interactive_revoked_packet(session_id):
    from security.verification import verify_message
    session = _revoked_key_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "submitted":
        return None, "Submit the signed packet after revocation before running verification."
    if session["verification"] is not None:
        return None, "Verification has already been run."
    crypto_valid = verify_signature(session["public_key"], session["payload"], session["signature"])
    verdict = verify_message(
        public_key=session["public_key"], signature=session["signature"],
        sender=session["sender"], receiver=session["receiver"],
        timestamp=session["timestamp"], timestamp_datetime=session["timestamp_datetime"],
        nonce=session["nonce"], message=session["message"],
        expected_content_hash=session["content_hash"], sender_known=True,
        used_nonces=set(), max_age_seconds=300, now=datetime.now(timezone.utc),
        key_revoked=session["key_status"] == "REVOKED",
    )
    session["verification"] = {
        "cryptographic_signature_valid": crypto_valid,
        "key_status": session["key_status"], "verdict": verdict.value,
    }
    session["stage"] = "verified"
    detected = crypto_valid and session["key_status"] == "REVOKED" and verdict.value == "REVOKED_KEY"
    return {
        "stage": "verified", "cryptographic_signature_valid": crypto_valid,
        "key_status": session["key_status"], "verdict": verdict.value,
        "detected": detected,
        "explanation": (
            "The signature remains mathematically valid, but the receiver rejects it because the signing key is revoked."
            if detected else "The expected revoked-key rejection was not produced. Review the verification output."
        ),
    }, None


def complete_interactive_revoked_key(session_id):
    session = _revoked_key_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "verified":
        return None, "Run revoked-key verification before generating the evidence report."
    now = datetime.now(timezone.utc)
    verification = session["verification"]
    detected = (
        verification["cryptographic_signature_valid"]
        and verification["key_status"] == "REVOKED"
        and verification["verdict"] == "REVOKED_KEY"
    )
    session["stage"] = "completed"
    return {
        "stage": "completed", "detected": detected,
        "verdict": "REVOKED_KEY_REJECTED" if detected else "UNEXPECTED_RESULT",
        "explanation": "The receiver rejected a correctly signed packet because its signing key had been revoked before submission." if detected else "The revoked-key packet was not rejected as expected.",
        "evidence": {"evidence_id": f"DEMO-REVOKED-{now.strftime('%Y%m%d%H%M%S%f')}",
                     "recorded": False,
                     "note": "Temporary demonstration evidence only. No permanent ledger entry or real key registry was modified."},
        "safety": {"simulation": True, "real_user_data": False,
                   "production_keys_modified": False, "production_ledger_modified": False},
    }, None


# ---------------------------------------------------------------------------
# Interactive Ledger Tampering Lab (isolated in-memory sample chain)
# ---------------------------------------------------------------------------
import json as _ledger_json

_LEDGER_TAMPER_SESSIONS = {}
_LEDGER_TAMPER_LOCK = threading.Lock()


def _ledger_demo_hash(record):
    encoded = _ledger_json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def prepare_interactive_ledger_tampering():
    now = datetime.now(timezone.utc)
    session_id = uuid.uuid4().hex
    records = [
        {"index": 1, "event": "MESSAGE_CREATED", "actor": "alice.demo", "details": "Created signed project approval", "timestamp": now.isoformat()},
        {"index": 2, "event": "MESSAGE_VERIFIED", "actor": "receiver.demo", "details": "Signature and content hash verified", "timestamp": now.isoformat()},
        {"index": 3, "event": "EVIDENCE_STORED", "actor": "ledger.demo", "details": "Evidence record committed", "timestamp": now.isoformat()},
    ]
    chain = []
    previous_hash = "GENESIS"
    for record in records:
        record_hash = _ledger_demo_hash({"record": record, "previous_hash": previous_hash})
        chain.append({"record": record, "previous_hash": previous_hash, "record_hash": record_hash})
        previous_hash = record_hash
    _LEDGER_TAMPER_SESSIONS[session_id] = {
        "created_at": now, "chain": chain, "stage": "prepared",
        "tampered_chain": None, "verification": None,
    }
    return {
        "session_id": session_id,
        "records": [{"index": x["record"]["index"], "event": x["record"]["event"],
                     "actor": x["record"]["actor"], "details": x["record"]["details"],
                     "previous_hash": x["previous_hash"], "record_hash": x["record_hash"]}
                    for x in chain],
        "explanation": "A disposable three-record hash chain has been created. Each record hash includes its contents and the previous record hash.",
        "safety": {"simulation": True, "real_user_data": False, "permanent_ledger_modified": False},
    }


def _ledger_tamper_session(session_id):
    session = _LEDGER_TAMPER_SESSIONS.get(session_id)
    if not session:
        return None
    if (datetime.now(timezone.utc) - session["created_at"]).total_seconds() > _INTERACTIVE_DEMO_TTL_SECONDS:
        _LEDGER_TAMPER_SESSIONS.pop(session_id, None)
        return None
    return session


def tamper_interactive_ledger_record(session_id, modified_details):
    session = _ledger_tamper_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "prepared":
        return None, "A record can only be modified once, before integrity verification."
    if not isinstance(modified_details, str) or not modified_details.strip():
        return None, "Enter modified record details."
    if len(modified_details) > 500:
        return None, "Modified details must be 500 characters or fewer."
    original = session["chain"][1]
    changed = [dict(item) for item in session["chain"]]
    changed_record = dict(changed[1]["record"])
    changed_record["details"] = modified_details
    changed[1] = dict(changed[1], record=changed_record)
    session["tampered_chain"] = changed
    session["stage"] = "tampered"
    return {
        "stage": "tampered", "record_index": 2,
        "original_details": original["record"]["details"],
        "modified_details": modified_details,
        "stored_hash_unchanged": True,
        "explanation": "Record 2 has been changed, but its stored hash and the following record's previous-hash reference have not been recalculated.",
    }, None


def verify_interactive_ledger_chain(session_id):
    session = _ledger_tamper_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "tampered":
        return None, "Modify a ledger record before running integrity verification."
    if session["verification"] is not None:
        return None, "Integrity verification has already been performed."
    chain = session["tampered_chain"]
    results = []
    expected_previous = "GENESIS"
    for item in chain:
        calculated = _ledger_demo_hash({"record": item["record"], "previous_hash": item["previous_hash"]})
        record_hash_valid = calculated == item["record_hash"]
        link_valid = item["previous_hash"] == expected_previous
        results.append({"index": item["record"]["index"], "record_hash_valid": record_hash_valid, "chain_link_valid": link_valid})
        expected_previous = item["record_hash"]
    detected = not all(x["record_hash_valid"] and x["chain_link_valid"] for x in results)
    session["verification"] = {"detected": detected, "records": results}
    session["stage"] = "verified"
    return {
        "stage": "verified", "detected": detected, "records": results,
        "invalid_record_indexes": [x["index"] for x in results if not x["record_hash_valid"] or not x["chain_link_valid"]],
        "explanation": "The modified record no longer matches its stored hash, so the hash-chain integrity check detects tampering." if detected else "No ledger modification was detected.",
    }, None


def complete_interactive_ledger_tampering(session_id):
    session = _ledger_tamper_session(session_id)
    if not session:
        return None, "Demo session not found or expired. Prepare a new scenario."
    if session["stage"] != "verified":
        return None, "Run ledger integrity verification before generating the evidence report."
    now = datetime.now(timezone.utc)
    detected = session["verification"]["detected"]
    session["stage"] = "completed"
    return {
        "stage": "completed", "detected": detected,
        "verdict": "LEDGER_TAMPERING_DETECTED" if detected else "NO_TAMPERING_DETECTED",
        "explanation": "The ledger record was modified and the stored hash chain no longer validates." if detected else "The ledger chain passed integrity verification.",
        "evidence": {"evidence_id": f"DEMO-LEDGER-{now.strftime('%Y%m%d%H%M%S%f')}",
                     "recorded": False, "note": "Temporary demonstration evidence only. The production evidence ledger was never modified."},
        "safety": {"simulation": True, "real_user_data": False, "permanent_ledger_modified": False},
    }, None
