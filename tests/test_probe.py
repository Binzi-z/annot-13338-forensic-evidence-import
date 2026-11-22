"""Environment sanity: the runtime this tool targets must be present.

Windows evidence tooling assumes: Python >= 3.10, Ed25519 from `cryptography`,
and `msvcrt` for cross-process locking on Windows.
"""

import os
import sys


def test_python_version():
    assert sys.version_info >= (3, 10), sys.version


def test_cryptography_ed25519_available():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    assert k.public_key() is not None


def test_windows_locking_primitives():
    if os.name == "nt":
        import msvcrt  # noqa: F401
