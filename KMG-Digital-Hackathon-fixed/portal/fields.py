"""ИБ-04: authenticated encryption of personal data fields (AES-256-SIV, RFC 5297).

SIV is deterministic, so exact lookups (login by username, filters by e-mail) keep working,
while values in the database are ciphertext bound to model and field name. The key is derived
from runtime/keys/data.key (created by setup_local.py, stored apart from the database).
"""
import base64
from functools import lru_cache
from django.conf import settings
from django.db import models
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = 'enc1:'


@lru_cache(maxsize=1)
def _cipher():
    key = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'helpdesk personal data fields').derive(settings.DATA_KEY_FILE.read_bytes())
    return AESSIV(key)


class EncryptedFieldMixin:
    def _aad(self):
        return [self.model._meta.label.encode(), self.attname.encode()]

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value in (None, '') or (isinstance(value, str) and value.startswith(PREFIX)):
            return value
        return PREFIX + base64.urlsafe_b64encode(_cipher().encrypt(str(value).encode(), self._aad())).decode()

    def from_db_value(self, value, expression, connection):
        if not value or not value.startswith(PREFIX):
            return value
        return _cipher().decrypt(base64.urlsafe_b64decode(value[len(PREFIX):]), self._aad()).decode()


class EncryptedCharField(EncryptedFieldMixin, models.CharField):
    pass


class EncryptedEmailField(EncryptedFieldMixin, models.EmailField):
    pass
