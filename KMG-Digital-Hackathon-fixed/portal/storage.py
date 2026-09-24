import io, os, uuid
from django.core.files.storage import FileSystemStorage
from django.core.files.base import ContentFile, File
from django.conf import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AttachmentStorage(FileSystemStorage):
    def _save(self, name, content):
        nonce = os.urandom(12)
        encrypted = nonce + AESGCM(settings.DATA_KEY_FILE.read_bytes()[:32]).encrypt(nonce, content.read(), b'attachment')
        return super()._save('attachments/' + uuid.uuid4().hex + '.dat', ContentFile(encrypted))
    def _open(self, name, mode='rb'):
        with super()._open(name, 'rb') as f:
            raw = f.read()
        content = AESGCM(settings.DATA_KEY_FILE.read_bytes()[:32]).decrypt(raw[:12], raw[12:], b'attachment')
        return File(io.BytesIO(content), name=name)
