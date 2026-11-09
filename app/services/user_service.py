from app.extensions import db
from app.models import User


def register_user(username, email, password):

    # Check whether username already exists
    existing_username = User.query.filter_by(
        username=username
    ).first()

    if existing_username:
        return None, "Username already exists"

    # Check whether email already exists
    existing_email = User.query.filter_by(
        email=email
    ).first()

    if existing_email:
        return None, "Email already exists"

    # Create new user
    user = User(
        username=username,
        email=email
    )

    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return user, None