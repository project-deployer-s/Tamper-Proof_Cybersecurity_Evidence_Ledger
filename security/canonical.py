import json


def create_canonical_payload(sender, receiver, timestamp, nonce, message):
    payload = {
        "sender": sender,
        "receiver": receiver,
        "timestamp": timestamp,
        "nonce": nonce,
        "message": message
    }

    canonical_json = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False
    )

    return canonical_json.encode("utf-8")