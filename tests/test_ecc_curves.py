#!/usr/bin/env python3
"""
ECC Curve Tests: NIST P-384 key generation + sign/verify + encrypt/decrypt
against slot 0 (the jcecard implementation).

Shared GPG helper lives in ``tests/gpg_card_helper.py``. Slot-1 (Nitrokey)
tests live in their own file — this one stays focused on slot 0.

Prerequisites:
- pcscd running with the jcecard IFD handler installed
- GnuPG + pinentry-loopback allowed for the user's gpg-agent

The test does not pin a specific reader. If both slots are visible,
scdaemon picks the first compatible card — typically slot 0 — unless
reader-port is set in ``~/.gnupg/scdaemon.conf``.
"""

import pytest

from tests.gpg_card_helper import GPGCardHelper


@pytest.fixture
def gpg_helper():
    """Provide a GPG card helper instance (slot 0 — jcecard default)."""
    helper = GPGCardHelper(timeout=120)
    yield helper


class TestNISTP384:
    """Test NIST P-384 curve key generation and operations on slot 0."""

    EMAIL = "p384test@example.com"

    def test_generate_p384_keys(self, gpg_helper):
        """Generate NIST P-384 keys on card."""
        gpg_helper.delete_keys_by_email(self.EMAIL)
        gpg_helper.factory_reset()

        success = gpg_helper.generate_p384_keys(user_email=self.EMAIL)
        assert success, "Failed to generate NIST P-384 keys"

    def test_p384_sign_verify(self, gpg_helper):
        """Test signing with NIST P-384 key."""
        success = gpg_helper.test_sign_and_verify(self.EMAIL)
        assert success, "NIST P-384 sign/verify failed"

    def test_p384_encrypt_decrypt(self, gpg_helper):
        """Test encryption with NIST P-384 key."""
        success = gpg_helper.test_encrypt_and_decrypt(self.EMAIL)
        assert success, "NIST P-384 encrypt/decrypt failed"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
