from security.verdicts import Verdict


def test_all_verdicts_exist():
    assert Verdict.GENUINE.value == "GENUINE"
    assert Verdict.TAMPERED.value == "TAMPERED"
    assert Verdict.INVALID_SIGNATURE.value == "INVALID_SIGNATURE"
    assert Verdict.UNKNOWN_SENDER.value == "UNKNOWN_SENDER"
    assert Verdict.REPLAY.value == "REPLAY"
    assert Verdict.EXPIRED.value == "EXPIRED"
    assert Verdict.REVOKED_KEY.value == "REVOKED_KEY"