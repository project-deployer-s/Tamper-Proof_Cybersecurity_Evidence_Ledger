from app.extensions import db
from app.models import User, PublicKey


def register_public_key(user_id, public_key, algorithm="ECDSA-P256"):

    # Check whether user exists
    user = db.session.get(User, user_id)

    if not user:
        return None, "User not found"

    # Check public key input
    if not public_key:
        return None, "Public key is required"

    if algorithm != "ECDSA-P256":
        return None, "Unsupported algorithm"

    # Create public key record
    key = PublicKey(
        user_id=user_id,
        public_key=public_key,
        algorithm=algorithm
    )

    db.session.add(key)
    db.session.commit()

    return key, None