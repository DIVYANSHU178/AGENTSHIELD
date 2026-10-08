"""
AgentShield — SigningKeyManager (Phase 1.2).

Produces and verifies Ed25519 signatures for the v2 ExecutionAuthorizationToken,
publishes public keys to EOS, and fails CLOSED whenever signing material is
unavailable in a production environment.

Guarantees:
- The private key is loaded from an explicit operator-provided secret or a
  development auto-generated keypair under ``.keys/`` (never in production).
- ``has_signing_key()`` is the single authority for signing availability;
  every mint path checks it and fails closed when it is False.
- Public keys serialize as base64 of the RAW 32-byte public key (protocol
  §3.2) so EOS can parse them without PEM.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import threading
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.config.settings import settings, API_DIR
from app.core.observability import get_logger

logger = get_logger("agentshield.security.keys")

SIGNING_ALGORITHM_ED25519 = "ed25519"

_KEYS_DIR_NAME = ".keys"
_PRIVATE_KEY_FILENAME = "as_signing_ed25519.key"
_PUBLIC_KEY_FILENAME = "as_signing_ed25519.pub"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _raw_b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class SigningKeyError(Exception):
    """Base error for signing key availability/loading failures."""


class SigningKeyManager:
    """
    Manages the active Ed25519 private key and the published public-key map.
    """

    def __init__(self, configured_settings=None, keys_dir: Optional[str] = None) -> None:
        self._s = configured_settings or settings
        if keys_dir is None:
            keys_dir = os.path.join(API_DIR, _KEYS_DIR_NAME)
        self._keys_dir = keys_dir
        self._lock = threading.Lock()
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._load_error: Optional[str] = None

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------
    def has_signing_key(self) -> bool:
        """True when an active private signing key is loaded and usable."""
        with self._lock:
            if self._private_key is not None:
                return True
        try:
            self._ensure_loaded()
            return self._private_key is not None
        except Exception as exc:
            logger.error(f"[SigningKeyManager] signing key unavailable: {exc}")
            return False

    def signing_unavailable_reason(self) -> Optional[str]:
        """Human-readable reason why signing is unavailable (None when OK)."""
        if self.has_signing_key():
            return None
        return self._load_error or (
            "No AgentShield signing private key configured and dev auto-generation "
            "is disabled or forbidden in this environment."
        )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    @property
    def issuer(self) -> str:
        return str(getattr(self._s, "AGENTSHIELD_SIGNING_ISSUER", None) or "eos.agentshield")

    @property
    def active_key_id(self) -> str:
        return str(getattr(self._s, "AGENTSHIELD_SIGNING_KEY_ID", None) or "v1")

    @property
    def algorithm(self) -> str:
        return SIGNING_ALGORITHM_ED25519

    # ------------------------------------------------------------------
    # Key loading (private)
    # ------------------------------------------------------------------
    def _ensure_loaded(self) -> None:
        with self._lock:
            if self._private_key is not None:
                return
            if self._load_error is not None:
                raise SigningKeyError(self._load_error)
            try:
                self._private_key = self._resolve_private_key()
            except Exception as exc:
                self._load_error = str(exc)
                logger.error(f"[SigningKeyManager] failed to load signing key: {exc}")
                raise SigningKeyError(str(exc)) from exc

    def _resolve_private_key(self):
        env_b64 = getattr(self._s, "AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64", None)
        if env_b64 and str(env_b64).strip():
            return self._load_from_b64(str(env_b64).strip())

        env_file = getattr(self._s, "AGENTSHIELD_SIGNING_PRIVATE_KEY_FILE", None)
        if env_file and str(env_file).strip() and os.path.isfile(str(env_file).strip()):
            return self._load_from_pem_path(str(env_file).strip())

        if self._dev_autogen_allowed():
            return self._load_or_generate_dev_keypair()

        self._load_error = (
            "No signing private key available (env/file unset) and dev "
            "auto-generation is not permitted in environment "
            f"'{getattr(self._s, 'ENVIRONMENT', 'unknown')}'."
        )
        raise SigningKeyError(self._load_error)

    def _dev_autogen_allowed(self) -> bool:
        # Phase 2.0 / F11 — production guard. Auto-generation of an Ed25519
        # signing authority key is a DEVELOPMENT/QA/TEST convenience ONLY and
        # must never silently become production authority:
        #   * known production environments are always rejected;
        #   * UNKNOWN / ambiguous environments (staging, prod-like, typos,
        #     anything not explicitly listed) are REJECTED — fail closed — so
        #     a misconfigured deployment can never auto-create signing material;
        #   * explicit dev/test/QA/CI environments may use autogen if the
        #     AGENTSHIELD_SIGNING_DEV_AUTOGEN switch remains enabled.
        env = str(getattr(self._s, "ENVIRONMENT", "development") or "development").lower()
        if env in ("production", "prod"):
            return False
        _DEV_CONTEXTS = {
            "development", "dev", "local",
            "test", "testing", "unittest", "pytest",
            "qa", "test_qa",
            "ci", "integration", "staging-test",
        }
        if env not in _DEV_CONTEXTS:
            return False
        return bool(getattr(self._s, "AGENTSHIELD_SIGNING_DEV_AUTOGEN", True))

    def _load_from_b64(self, b64_value: str) -> ed25519.Ed25519PrivateKey:
        try:
            pem_bytes = base64.b64decode(b64_value)
            return serialization.load_pem_private_key(pem_bytes, password=None)
        except Exception as exc:
            raise SigningKeyError(f"Invalid AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64: {exc}") from exc

    def _load_from_pem_path(self, path: str) -> ed25519.Ed25519PrivateKey:
        try:
            with open(path, "rb") as fh:
                return serialization.load_pem_private_key(fh.read(), password=None)
        except Exception as exc:
            raise SigningKeyError(f"Failed to load signing private key '{path}': {exc}") from exc

    def _load_or_generate_dev_keypair(self) -> ed25519.Ed25519PrivateKey:
        keys_dir = self._keys_dir
        os.makedirs(keys_dir, exist_ok=True)
        priv_path = os.path.join(keys_dir, _PRIVATE_KEY_FILENAME)
        pub_path = os.path.join(keys_dir, _PUBLIC_KEY_FILENAME)

        generated = False
        if os.path.isfile(priv_path):
            try:
                return self._load_from_pem_path(priv_path)
            except SigningKeyError:
                logger.warning("[SigningKeyManager] Dev key unreadable; regenerating.")

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(priv_path, "wb") as fh:
            fh.write(priv_pem)
        with open(pub_path, "wb") as fh:
            fh.write(pub_pem)
        generated = True
        logger.info(
            f"[SigningKeyManager] Generated dev Ed25519 keypair at {keys_dir} "
            f"(generated={generated})."
        )
        return private_key

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------
    def sign(self, payload: bytes) -> str:
        """
        Sign the canonical payload bytes with the active private key.
        Returns a base64url (no padding) signature. Raises SigningKeyError when
        no signing key is available (fail closed).
        """
        self._ensure_loaded()
        assert self._private_key is not None
        signature = self._private_key.sign(payload)
        return _b64url_encode(signature)

    def verify(self, payload: bytes, signature_b64url: str, key_id: Optional[str] = None) -> bool:
        """
        Verify a base64url signature against the given payload using the key for
        ``key_id`` (defaults to the active key). Fails closed on any error.
        """
        try:
            public_key = self.public_key_object(key_id)
            signature_bytes = _b64url_decode(signature_b64url)
            public_key.verify(signature_bytes, payload)
            return True
        except (InvalidSignature, Exception):
            return False

    # ------------------------------------------------------------------
    # Public material
    # ------------------------------------------------------------------
    def public_key_object(self, key_id: Optional[str] = None) -> ed25519.Ed25519PublicKey:
        kid = key_id or self.active_key_id
        raw_b64 = self.public_key_map().get(kid)
        if not raw_b64:
            raise SigningKeyError(f"No public key published for key_id '{kid}'.")
        try:
            raw = base64.b64decode(str(raw_b64))
            return ed25519.Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise SigningKeyError(f"Invalid public key material for key_id '{kid}': {exc}") from exc

    def active_public_key_raw_b64(self) -> str:
        """base64 of the RAW 32-byte active public key (protocol §3.2)."""
        self._ensure_loaded()
        assert self._private_key is not None
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _raw_b64_encode(raw)

    def public_key_info(self) -> Dict[str, str]:
        """Active-key identity record returned by GET /public-key."""
        return {
            "key_id": self.active_key_id,
            "algorithm": self.algorithm,
            "public_key_base64": self.active_public_key_raw_b64(),
            "issuer": self.issuer,
        }

    def public_key_map(self) -> Dict[str, str]:
        """
        Full published map {key_id: raw-b64 public key}: the active dev/active
        key plus any operator-supplied rotation keys from
        ``AGENTSHIELD_SIGNING_PUBLIC_KEYS`` (JSON map).
        """
        result: Dict[str, str] = {}
        if self.has_signing_key():
            result[self.active_key_id] = self.active_public_key_raw_b64()
        extra_raw = getattr(self._s, "AGENTSHIELD_SIGNING_PUBLIC_KEYS", None)
        if extra_raw and str(extra_raw).strip():
            try:
                extra = json.loads(str(extra_raw))
                if isinstance(extra, dict):
                    for kid, raw_b64 in extra.items():
                        if isinstance(kid, str) and isinstance(raw_b64, str) and raw_b64.strip():
                            result[str(kid)] = raw_b64
            except Exception as exc:
                logger.warning(f"[SigningKeyManager] invalid AGENTSHIELD_SIGNING_PUBLIC_KEYS: {exc}")
        return result


# --------------------------------------------------------------------------
# Singleton
# --------------------------------------------------------------------------
key_manager: Optional[SigningKeyManager] = None


def get_signing_key_manager() -> SigningKeyManager:
    global key_manager
    if key_manager is None:
        key_manager = SigningKeyManager()
    return key_manager