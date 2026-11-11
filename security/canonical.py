
import json


def create_canonical_payload(
    sender,
    receiver,
    timestamp,
    nonce,
    message,
    attachment_hashes=None
):
    payload = {
        "sender": sender,
        "receiver": receiver,
        "timestamp": timestamp,
        "nonce": nonce,
        "message": message
    }

    # Include attachment hashes only when attachments exist.
    if attachment_hashes:
        payload["attachment_hashes"] = sorted(attachment_hashes)

    canonical_json = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False
    )

    return canonical_json.encode("utf-8")
