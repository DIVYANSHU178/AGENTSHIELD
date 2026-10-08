"""
AgentShield — Generate the Ed25519 signing keypair (Phase 1.2).

Writes:
  <repo>/apps/api/.keys/as_signing_ed25519.key   (PKCS8 PEM private key)
  <repo>/apps/api/.keys/as_signing_ed25519.pub   (SubjectPublicKeyInfo PEM)

Advisory: keep the private key OUT of source control and instead export its
base64 into AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64 for production, or point
AGENTSHIELD_SIGNING_PRIVATE_KEY_FILE at the PEM file.

Usage:
  python scripts/generate_ed25519_keys.py [--output DIR] [--print]
"""

import argparse
import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

DEFAULT_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "apps", "api", ".keys")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AgentShield Ed25519 signing keypair.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output directory for keypair files.")
    parser.add_argument("--print", action="store_true", help="Print the base64 private key for env export.")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = os.path.join(args.output, "as_signing_ed25519.key")
    pub_path = os.path.join(args.output, "as_signing_ed25519.pub")

    with open(priv_path, "wb") as fh:
        fh.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(pub_path, "wb") as fh:
        fh.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"Wrote private key: {os.path.normpath(priv_path)}")
    print(f"Wrote public key:  {os.path.normpath(pub_path)}")

    if args.print:
        with open(priv_path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode("ascii")
        print("\nExport for production (AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64):")
        print(b64)
    return 0


if __name__ == "__main__":
    sys.exit(main())