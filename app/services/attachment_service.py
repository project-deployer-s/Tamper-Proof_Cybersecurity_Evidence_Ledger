
import hashlib
import uuid

from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import MessageAttachment
from app.services.storage_service import upload_file


ALLOWED_EXTENSIONS = {
    "pdf", "txt", "csv", "png",
    "jpg", "jpeg", "docx"
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def save_attachment(file, message_id):
    """Validate, upload and register an attachment."""

    if not file or not file.filename:
        return None, "No file selected"

    original_name = secure_filename(file.filename)

    if not original_name:
        return None, "Invalid filename"

    extension = (
        original_name.rsplit(".", 1)[-1].lower()
        if "." in original_name else ""
    )

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

    mime_type = file.mimetype or "application/octet-stream"

    # Upload to private Supabase Storage.
    try:
        upload_file(
            storage_key=stored_name,
            content=content,
            content_type=mime_type
        )
    except Exception:
        return None, "Attachment storage upload failed"

    # Register attachment metadata.
    attachment = MessageAttachment(
        message_id=message_id,
        original_filename=original_name,
        stored_filename=stored_name,
        mime_type=mime_type,
        file_size=len(content),
        sha256_hash=file_hash
    )

    db.session.add(attachment)

    return attachment, None
