import json


def create_canonical_payload(
    sender,
    receiver,
    timestamp,
    nonce,
    message,
    attachment_hashes=None,
    expiry_seconds=None
):
    payload = {
        "sender": sender,
        "receiver": receiver,
        "timestamp": timestamp,
        "nonce": nonce,
        "message": message
    }

    if attachment_hashes:
        payload["attachment_hashes"] = sorted(attachment_hashes)

    # Include expiry only for messages with a finite duration.
    # Omitting it preserves the canonical format of old messages.
    if expiry_seconds is not None:
        payload["expiry_seconds"] = expiry_seconds

    canonical_json = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False
    )

    return canonical_json.encode("utf-8")