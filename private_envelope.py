"""AES-GCM-SIV data privacy. Authentication never grants execution authority."""
from dataclasses import dataclass
import json
import os
import re

MAGIC = b'BTCENC01'
OVERHEAD = len(MAGIC) + 12 + 16


class PrivacyError(Exception):
    pass

try:
    from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
except ImportError:
    raise PrivacyError('privacy_library_unavailable') from None

def parse_key(text):
    import base64
    try:
        if not isinstance(text,str) or len(text)!=44:raise ValueError()
        raw=base64.b64decode(text,validate=True)
        if len(raw)!=32 or base64.b64encode(raw).decode()!=text:raise ValueError()
        return raw
    except Exception:raise PrivacyError('privacy_key_missing_or_invalid') from None


@dataclass(frozen=True)
class Context:
    repository: str
    repository_id: int
    store_id: str
    purpose: str

    def __post_init__(self):
        if (not isinstance(self.repository, str)
                or not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', self.repository)
                or type(self.repository_id) is not int or not 0 < self.repository_id < 2**63
                or not isinstance(self.store_id, str)
                or not re.fullmatch(r'[0-9a-f]{32}', self.store_id)
                or self.purpose not in ('private-runtime-capsule', 'private-checkpoint')):
            raise PrivacyError('privacy_context_invalid')

    def aad(self):
        return json.dumps(dict(schema='btc-private-aead-v1',
            repository=self.repository, repository_id=self.repository_id,
            store_id=self.store_id, purpose=self.purpose),
            sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


class Cipher:
    def __init__(self, key, context, *, maximum):
        if (not isinstance(key, bytes) or len(key) != 32 or not isinstance(context, Context)
                or type(maximum) is not int or not 1 <= maximum <= 8 * 1024 * 1024):
            raise PrivacyError('privacy_configuration_invalid')
        try:
            self._cipher = AESGCMSIV(key)
        except (ValueError, UnsupportedAlgorithm):
            raise PrivacyError('privacy_algorithm_unavailable') from None
        self.context, self.maximum = context, maximum
        self._aad = context.aad()

    def seal(self, raw):
        if not isinstance(raw, bytes) or not 0 < len(raw) <= self.maximum:
            raise PrivacyError('privacy_plaintext_size_invalid')
        # Always CSPRNG; no user/clock/revision-derived nonce and no nonce fallback.
        nonce = os.urandom(12)
        encrypted = self._cipher.encrypt(nonce, raw, self._aad)
        return MAGIC + nonce + encrypted

    def open(self, encrypted):
        if (not isinstance(encrypted, bytes)
                or not OVERHEAD < len(encrypted) <= self.maximum + OVERHEAD
                or encrypted[:len(MAGIC)] != MAGIC):
            raise PrivacyError('privacy_ciphertext_format_invalid')
        try:
            raw = self._cipher.decrypt(encrypted[len(MAGIC):len(MAGIC)+12],
                encrypted[len(MAGIC)+12:], self._aad)
        except (InvalidTag, ValueError, OverflowError):
            raise PrivacyError('privacy_authentication_failed') from None
        if not 0 < len(raw) <= self.maximum:
            raise PrivacyError('privacy_plaintext_size_invalid')
        return raw


