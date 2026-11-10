
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import User


def register_user(username, email, password):
    """Register a new user with securely hashed password."""

    # 1. Check whether username already exists
    existing_username = User.query.filter_by(
        username=username
    ).first()

    if existing_username:
        return None, "Username already exists"

    # 2. Check whether email already exists
    existing_email = User.query.filter_by(
        email=email
    ).first()

    if existing_email:
        return None, "Email already exists"

    try:
        # 3. Create new user
        user = User(
            username=username,
            email=email
        )

        # 4. Hash password
        user.set_password(password)

        # 5. Save user
        db.session.add(user)
        db.session.commit()

        return user, None

    except IntegrityError:
        db.session.rollback()

        return None, "Username or email already exists"

    except Exception as exc:
        db.session.rollback()

        print("USER REGISTRATION ERROR:", repr(exc))

        return None, "User registration failed"
