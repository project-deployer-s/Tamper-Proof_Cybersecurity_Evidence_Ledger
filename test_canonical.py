from security.canonical import create_canonical_payload


payload = create_canonical_payload(
    sender="Alice",
    receiver="Bob",
    timestamp="2026-10-05T12:00:00Z",
    nonce="abc123",
    message="Hello Bob"
)

print(payload.decode("utf-8"))