from security.hashing import calculate_sha256


def test_sha256():
    data = b"abc"

    result = calculate_sha256(data)

    assert result == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )