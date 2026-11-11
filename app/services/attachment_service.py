
import hashlib
import uuid
from pathlib import Path

from flask import current_app
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import MessageAttachment


ALLOWED_EXTENSIONS = {
    "pdf", "txt", "csv", "png",
    "jpg", "jpeg", "docx"
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def save_attachment(file, message_id):
    """Validate, hash, store and register an attachment."""

    if not file or not file.filename:
        return None, "No file selected"

    original_name = secure_filename(file.filename)

    if not original_name:
        return None, "Invalid filename"

    extension = original_name.rsplit(".", 1)[-1].lower() \
        if "." in original_name else ""

    if extension not in ALLOWED_EXTENSIONS:
        return None, "File type not allowed"

    content = file.read(MAX_FILE_SIZE + 1)

    if not content:
        return None, "Empty files are not allowed"

    if len(content) > MAX_FILE_SIZE:
        return None, "File exceeds the 10 MB limit"

    # Calculate SHA-256 hash.
    file_hash = hashlib.sha256(content).hexdigest()

    # Generate a unique storage filename.
    stored_name = f"{uuid.uuid4().hex}.{extension}"

    upload_dir = Path(current_app.instance_path) / "attachments"
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_path = upload_dir / stored_name

    # Store file.
    file_path.write_bytes(content)

    attachment = MessageAttachment(
        message_id=message_id,
        original_filename=original_name,
        stored_filename=stored_name,
        mime_type=file.mimetype or "application/octet-stream",
        file_size=len(content),
        sha256_hash=file_hash
    )

    db.session.add(attachment)

    return attachment, None
