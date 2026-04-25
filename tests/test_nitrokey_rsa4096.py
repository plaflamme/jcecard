#!/usr/bin/env python3
"""
RSA 4096 key generation + sign/verify + encrypt/decrypt against slot 1
(the upstream opcard-rs running on a host-side Trussed service).

The original version of this test generated an RSA-4096 primary off-card
and uploaded it to slot 1 via ``gpg --edit-key ... keytocard``. That
flow tripped a "KEYTOCARD failed: Invalid time" error in
``gpg-agent 2.4.4`` (Ubuntu 24.04) — the agent's ``isotime2epoch``
parsing of a 2026 timestamp returns ``-1`` even though the value is
parseable in isolation. Rather than chase the gpg-agent bug, we
generate the keys **on-card** instead, which exercises the same code
paths in opcard-rs (``trussed-rsa-alloc`` → RSA-4096 keygen → fingerprint
+ status PUT DATA) without going through ``keytocard``.

Slot 1 must include the ``allowed_generation = ... | RSA_4096`` patch
in the vendored ``components/apps`` (ADR-1.6) and `trussed-rsa-alloc`
must be linked (it already is via the ``opcard`` cargo feature).

Skipped if slot 1 is not present (e.g. pcscd not running, or
``--no-default-features`` build).
"""

from __future__ import annotations

import os
import subprocess

import pytest

from tests.gpg_card_helper import (
    GPGCardHelper,
    NITROKEY_SLOT1_SUFFIX,
    find_reader_by_suffix,
)


KEY_EMAIL = "nk3-rsa4096@example.com"
KEY_NAME = "nk3-rsa4096-test"


@pytest.fixture(scope="class")
def nitrokey_helper(tmp_path_factory):
    """GPG helper pinned to slot 1 in a scratch GNUPGHOME.

    Skips the whole class if the Nitrokey slot is not found.
    """
    reader = find_reader_by_suffix(NITROKEY_SLOT1_SUFFIX)
    if reader is None:
        pytest.skip(
            f"Nitrokey slot (reader ending ' {NITROKEY_SLOT1_SUFFIX}') not found — "
            "is pcscd running with a nitrokey-enabled libifd_jcecard.so?"
        )

    gnupg_home = tmp_path_factory.mktemp("gnupg-nk3-rsa4096")
    os.chmod(gnupg_home, 0o700)
    helper = GPGCardHelper(
        timeout=600,  # RSA 4096 keygen on-card is slow.
        gnupg_home=str(gnupg_home),
        reader_port=reader,
    )
    print(f"\n[slot 1] Reader      : {reader}")
    print(f"[slot 1] GNUPGHOME   : {gnupg_home}")

    yield helper

    subprocess.run(
        ['gpgconf', '--kill', 'all'],
        env=helper.env,
        capture_output=True,
    )


class TestNitrokeyRSA4096:
    """RSA 4096 on slot 1 — real upstream opcard-rs + trussed-rsa-alloc.

    Mirrors ``TestNitrokeyP384`` but with RSA 4096 attributes set via
    ``gpg --edit-card → admin → key-attr → 1 (RSA) → 4096`` instead of
    the ECC menu. Confirms the real RSA software backend handles
    on-card keygen + signing + decryption end-to-end.
    """

    EMAIL = KEY_EMAIL

    def test_generate_rsa4096_keys(self, nitrokey_helper):
        """Generate RSA 4096 keys on slot 1."""
        nitrokey_helper.delete_keys_by_email(self.EMAIL)
        nitrokey_helper.factory_reset()

        success = nitrokey_helper.generate_rsa4096_keys(
            user_name=KEY_NAME, user_email=self.EMAIL
        )
        assert success, "RSA 4096 key generation failed on Nitrokey slot"

    def test_rsa4096_sign_verify(self, nitrokey_helper):
        """Detach-sign with the on-card RSA 4096 key and verify."""
        success = nitrokey_helper.test_sign_and_verify(self.EMAIL)
        assert success, "RSA 4096 sign/verify failed on Nitrokey slot"

    def test_rsa4096_encrypt_decrypt(self, nitrokey_helper):
        """Encrypt to the on-card RSA 4096 key and decrypt."""
        success = nitrokey_helper.test_encrypt_and_decrypt(self.EMAIL)
        assert success, "RSA 4096 encrypt/decrypt failed on Nitrokey slot"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
