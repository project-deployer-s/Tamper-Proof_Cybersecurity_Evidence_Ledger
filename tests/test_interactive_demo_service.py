from app.services.interactive_demo_service import (
    prepare_interactive_tampering,
    tamper_interactive_message,
    run_interactive_tampering_check,
    complete_interactive_tampering,
)


def test_interactive_tampering_requires_manual_stages():
    prepared = prepare_interactive_tampering()
    session_id = prepared["session_id"]

    assert prepared["signature_created"] is True
    assert prepared["safety"]["production_ledger_modified"] is False

    result, error = run_interactive_tampering_check(session_id, "hash")
    assert result is None
    assert "Submit" in error

    modified, error = tamper_interactive_message(
        session_id, "Transfer ₹50,000 to Rahul."
    )
    assert error is None
    assert modified["verification_started"] is False

    hash_result, error = run_interactive_tampering_check(session_id, "hash")
    assert error is None
    assert hash_result["status"] == "failed"

    signature_result, error = run_interactive_tampering_check(session_id, "signature")
    assert error is None
    assert signature_result["status"] == "failed"

    report, error = complete_interactive_tampering(session_id)
    assert error is None
    assert report["verdict"] == "TAMPERED"
    assert report["evidence"]["recorded"] is False


def test_interactive_tampering_rejects_unchanged_message():
    prepared = prepare_interactive_tampering()
    result, error = tamper_interactive_message(
        prepared["session_id"], prepared["original_message"]
    )
    assert result is None
    assert "Change the message" in error


def test_interactive_tampering_requires_both_checks_before_report():
    prepared = prepare_interactive_tampering()
    session_id = prepared["session_id"]
    tamper_interactive_message(session_id, "A changed sample message")
    result, error = complete_interactive_tampering(session_id)
    assert result is None
    assert "both" in error.lower()



def test_interactive_forgery_requires_manual_stages():
    from app.services.interactive_demo_service import (
        prepare_interactive_forgery,
        create_interactive_forged_signature,
        submit_interactive_forged_signature,
        verify_interactive_forged_signature,
        complete_interactive_forgery,
    )

    prepared = prepare_interactive_forgery()
    session_id = prepared["session_id"]

    # Verification cannot run before the learner creates and submits a forgery.
    result, error = verify_interactive_forged_signature(session_id)
    assert result is None
    assert "Submit" in error

    forged, error = create_interactive_forged_signature(session_id)
    assert error is None
    assert forged["verification_started"] is False

    submitted, error = submit_interactive_forged_signature(session_id)
    assert error is None
    assert submitted["submitted"] is True

    verification, error = verify_interactive_forged_signature(session_id)
    assert error is None
    assert verification["valid_for_sender"] is False
    assert verification["valid_for_attacker"] is True
    assert verification["detected"] is True

    report, error = complete_interactive_forgery(session_id)
    assert error is None
    assert report["verdict"] == "FORGED_SIGNATURE_REJECTED"
    assert report["evidence"]["recorded"] is False


def test_interactive_forgery_cannot_be_completed_before_verification():
    from app.services.interactive_demo_service import (
        prepare_interactive_forgery,
        complete_interactive_forgery,
    )

    prepared = prepare_interactive_forgery()
    report, error = complete_interactive_forgery(prepared["session_id"])
    assert report is None
    assert "verification" in error.lower()


def test_interactive_replay_requires_manual_stages():
    from app.services.interactive_demo_service import (
        prepare_interactive_replay, accept_interactive_replay_original,
        submit_interactive_replay, verify_interactive_replay,
        complete_interactive_replay,
    )

    prepared = prepare_interactive_replay()
    session_id = prepared["session_id"]

    # Replay cannot be submitted before the receiver accepts the original.
    result, error = submit_interactive_replay(session_id)
    assert result is None
    assert "Accept" in error

    accepted, error = accept_interactive_replay_original(session_id)
    assert error is None
    assert accepted["verdict"] == "GENUINE"
    assert accepted["nonce_recorded"] is True

    submitted, error = submit_interactive_replay(session_id)
    assert error is None
    assert submitted["same_message"] is True
    assert submitted["same_signature"] is True
    assert submitted["same_nonce"] is True

    verified, error = verify_interactive_replay(session_id)
    assert error is None
    assert verified["verdict"] == "REPLAY"
    assert verified["detected"] is True

    report, error = complete_interactive_replay(session_id)
    assert error is None
    assert report["verdict"] == "REPLAY_ATTACK_REJECTED"
    assert report["evidence"]["recorded"] is False


def test_interactive_replay_cannot_complete_before_verification():
    from app.services.interactive_demo_service import (
        prepare_interactive_replay, complete_interactive_replay,
    )
    prepared = prepare_interactive_replay()
    report, error = complete_interactive_replay(prepared["session_id"])
    assert report is None
    assert "verification" in error.lower()


def test_interactive_expired_signature_requires_manual_stages():
    from app.services.interactive_demo_service import (
        prepare_interactive_expired_signature,
        submit_interactive_expired_signature,
        verify_interactive_expired_signature,
        complete_interactive_expired_signature,
    )

    prepared = prepare_interactive_expired_signature()
    session_id = prepared["session_id"]
    assert prepared["age_seconds"] > prepared["validity_window_seconds"]

    report, error = complete_interactive_expired_signature(session_id)
    assert report is None
    assert "verification" in error.lower()

    submitted, error = submit_interactive_expired_signature(session_id)
    assert error is None
    assert submitted["submitted"] is True

    verification, error = verify_interactive_expired_signature(session_id)
    assert error is None
    assert verification["cryptographic_signature_valid"] is True
    assert verification["freshness_verdict"] == "EXPIRED"
    assert verification["detected"] is True

    report, error = complete_interactive_expired_signature(session_id)
    assert error is None
    assert report["verdict"] == "EXPIRED_SIGNATURE_REJECTED"
    assert report["evidence"]["recorded"] is False


def test_interactive_expired_signature_cannot_verify_before_submission():
    from app.services.interactive_demo_service import (
        prepare_interactive_expired_signature,
        verify_interactive_expired_signature,
    )
    prepared = prepare_interactive_expired_signature()
    result, error = verify_interactive_expired_signature(prepared["session_id"])
    assert result is None
    assert "submit" in error.lower()


def test_interactive_revoked_key_requires_manual_stages():
    from app.services.interactive_demo_service import (
        prepare_interactive_revoked_key, revoke_interactive_demo_key,
        submit_interactive_revoked_packet, verify_interactive_revoked_packet,
        complete_interactive_revoked_key,
    )

    prepared = prepare_interactive_revoked_key()
    session_id = prepared["session_id"]
    assert prepared["key_status"] == "TRUSTED"

    result, error = submit_interactive_revoked_packet(session_id)
    assert result is None
    assert "Revoke" in error

    revoked, error = revoke_interactive_demo_key(session_id)
    assert error is None
    assert revoked["key_status"] == "REVOKED"

    submitted, error = submit_interactive_revoked_packet(session_id)
    assert error is None
    assert submitted["submitted"] is True

    verification, error = verify_interactive_revoked_packet(session_id)
    assert error is None
    assert verification["cryptographic_signature_valid"] is True
    assert verification["key_status"] == "REVOKED"
    assert verification["verdict"] == "REVOKED_KEY"
    assert verification["detected"] is True

    report, error = complete_interactive_revoked_key(session_id)
    assert error is None
    assert report["verdict"] == "REVOKED_KEY_REJECTED"
    assert report["evidence"]["recorded"] is False


def test_interactive_revoked_key_cannot_complete_before_verification():
    from app.services.interactive_demo_service import (
        prepare_interactive_revoked_key, complete_interactive_revoked_key,
    )
    prepared = prepare_interactive_revoked_key()
    report, error = complete_interactive_revoked_key(prepared["session_id"])
    assert report is None
    assert "verification" in error.lower()


def test_interactive_ledger_tampering_requires_manual_stages():
    from app.services.interactive_demo_service import (
        prepare_interactive_ledger_tampering, tamper_interactive_ledger_record,
        verify_interactive_ledger_chain, complete_interactive_ledger_tampering,
    )
    prepared = prepare_interactive_ledger_tampering()
    sid = prepared["session_id"]
    assert len(prepared["records"]) == 3
    result, error = verify_interactive_ledger_chain(sid)
    assert result is None and "modify" in error.lower()
    changed, error = tamper_interactive_ledger_record(sid, "Unauthorized modification")
    assert error is None and changed["stored_hash_unchanged"] is True
    verified, error = verify_interactive_ledger_chain(sid)
    assert error is None and verified["detected"] is True
    assert verified["invalid_record_indexes"] == [2]
    report, error = complete_interactive_ledger_tampering(sid)
    assert error is None
    assert report["verdict"] == "LEDGER_TAMPERING_DETECTED"
    assert report["evidence"]["recorded"] is False


def test_interactive_ledger_cannot_complete_before_verification():
    from app.services.interactive_demo_service import (
        prepare_interactive_ledger_tampering, complete_interactive_ledger_tampering,
    )
    prepared = prepare_interactive_ledger_tampering()
    report, error = complete_interactive_ledger_tampering(prepared["session_id"])
    assert report is None
    assert "verification" in error.lower()
