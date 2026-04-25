#!/usr/bin/env python3
"""
NIST P-384 key generation + sign/verify + encrypt/decrypt against slot 1
(the upstream opcard-rs on a host-side Trussed service).

P-384 (and P-521) are only runnable on slot 1 because we enable the
`trussed/p384` + `trussed/p521` Cargo features in ifd-jcecard's
Cargo.toml. Without those, `components/apps`' `trussed-usbip` bypass
lets P-384 compile but the runtime dispatcher has no backend, so any
key generation or signing call would return an error.

The class is skipped gracefully if the slot-1 reader (suffix ``00 01``)
is not present — e.g. pcscd isn't running or ``libifd_jcecard.so`` was
built with ``--no-default-features``.
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


KEY_EMAIL = "nk3-p384@example.com"
KEY_NAME = "nk3-p384-test"


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

    gnupg_home = tmp_path_factory.mktemp("gnupg-nk3-p384")
    os.chmod(gnupg_home, 0o700)
    helper = GPGCardHelper(
        timeout=240,
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


class TestNitrokeyP384:
    """NIST P-384 on slot 1 — real upstream opcard-rs + Trussed p384.

    Mirrors `TestNISTP384` from ``test_ecc_curves.py`` (which targets
    slot 0) so a passing run against both files demonstrates the two
    cards behave consistently at the ECC-on-OpenPGP level.
    """

    EMAIL = KEY_EMAIL

    def test_generate_p384_keys(self, nitrokey_helper):
        """Generate NIST P-384 keys on slot 1."""
        nitrokey_helper.delete_keys_by_email(self.EMAIL)
        nitrokey_helper.factory_reset()

        success = nitrokey_helper.generate_p384_keys(
            user_name=KEY_NAME, user_email=self.EMAIL
        )
        assert success, "P-384 key generation failed on Nitrokey slot"

    def test_p384_sign_verify(self, nitrokey_helper):
        """Detach-sign with the on-card P-384 key and verify."""
        success = nitrokey_helper.test_sign_and_verify(self.EMAIL)
        assert success, "P-384 sign/verify failed on Nitrokey slot"

    def test_p384_encrypt_decrypt(self, nitrokey_helper):
        """Encrypt to the on-card P-384 key and decrypt."""
        success = nitrokey_helper.test_encrypt_and_decrypt(self.EMAIL)
        assert success, "P-384 encrypt/decrypt failed on Nitrokey slot"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
