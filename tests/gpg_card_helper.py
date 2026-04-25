"""
Shared GPG card test helper.

Used by ``test_ecc_curves.py`` (slot 0) and ``test_nitrokey_rsa4096.py``
(slot 1). Keeps pexpect/subprocess plumbing in one place so tests stay
focused on what they are actually exercising.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from typing import Optional

import pexpect


# Default PINs — shared by jcecard (slot 0) and a freshly-factory-reset
# Nitrokey (opcard-rs upstream defaults are 123456 / 12345678).
DEFAULT_USER_PIN = "123456"
DEFAULT_ADMIN_PIN = "12345678"

# pcscd labels each slot of an IFD handler with " NN NN" (reader index
# + slot index). With our handler reporting TAG_IFD_SLOTS_NUMBER=2,
# slot 0 is suffixed " 00 00" and slot 1 is suffixed " 00 01".
JCECARD_SLOT0_SUFFIX = "00 00"
NITROKEY_SLOT1_SUFFIX = "00 01"


def find_reader_by_suffix(suffix: str) -> Optional[str]:
    """Return the first PC/SC reader whose name ends with `suffix`.

    Returns ``None`` if pyscard is unavailable or no matching reader is
    present — callers use this to ``pytest.skip`` gracefully when the
    slot-1 Nitrokey reader is not up (e.g. pcscd not running, or the .so
    was built with ``--no-default-features``).
    """
    try:
        from smartcard.System import readers
    except Exception:
        return None
    for r in readers():
        name = str(r)
        if name.rstrip().endswith(suffix):
            return name
    return None


class GPGCardHelper:
    """Helper class to interact with GPG card operations via pexpect.

    When ``gnupg_home`` is provided, gpg/scdaemon run against an
    isolated GNUPGHOME — this is how the slot-1 test avoids clobbering
    the user's real keyring or the slot-0 test state running alongside.

    When ``reader_port`` is provided, an ``scdaemon.conf`` pinning gpg
    to that specific PC/SC reader is written into the GNUPGHOME before
    the first gpg invocation. This is how we route gpg to slot 1 while
    slot 0 is also visible to pcscd.
    """

    def __init__(
        self,
        timeout: int = 60,
        gnupg_home: Optional[str] = None,
        reader_port: Optional[str] = None,
    ):
        self.timeout = timeout
        self.env = os.environ.copy()
        if gnupg_home is not None:
            self.env['GNUPGHOME'] = gnupg_home
            self.gnupg_home = gnupg_home
        else:
            self.gnupg_home = os.environ.get(
                'GNUPGHOME', os.path.expanduser('~/.gnupg')
            )

        os.makedirs(self.gnupg_home, mode=0o700, exist_ok=True)
        if reader_port is not None:
            self._write_scdaemon_conf(reader_port)
            self._write_gpgagent_conf()

    def _write_gpgagent_conf(self) -> None:
        """Capture full gpg-agent debug output for forensics on test failures.

        Without this we have only `scdaemon.log`; some failures (notably
        ``KEYTOCARD`` rejected before any APDU is sent) live in the
        agent layer.
        """
        conf_path = os.path.join(self.gnupg_home, 'gpg-agent.conf')
        log_path = os.path.join(self.gnupg_home, 'gpg-agent.log')
        with open(conf_path, 'w') as f:
            f.write("debug-all\n")
            f.write(f"log-file {log_path}\n")
            f.write("allow-loopback-pinentry\n")
        os.chmod(conf_path, 0o600)

    def _write_scdaemon_conf(self, reader_port: str) -> None:
        """Pin scdaemon to a specific PC/SC reader.

        With two slots visible in pcscd, scdaemon enumerates both and
        can ping-pong between them during operations that trigger a
        card re-select (notably ``--edit-card`` / ``keytocard``). We
        therefore:

        - write ``reader-port`` with the full reader name (prefix match)
          **and** the numeric index form on a second line so scdaemon
          prefers the exact reader.
        - add ``pcsc-shared`` so we coexist with the user's system
          scdaemon rather than exclusive-locking the card.
        - kill any foreign scdaemon that is already holding PC/SC
          handles open (``$USER``-level, not just the scratch
          GNUPGHOME) — otherwise the daemon keeps both readers live.
        - also kill gpg-agent in the scratch home so it re-spawns
          scdaemon after the conf is on disk.
        """
        conf_path = os.path.join(self.gnupg_home, 'scdaemon.conf')
        log_path = os.path.join(self.gnupg_home, 'scdaemon.log')
        with open(conf_path, 'w') as f:
            f.write(f"reader-port {reader_port}\n")
            # Numeric index form (0-based): slot 1 is the second reader
            # pcscd advertises with our handler.
            f.write("reader-port 1\n")
            f.write("disable-ccid\n")
            f.write("pcsc-shared\n")
            # Full debug so we can see what PIN bytes scdaemon sends.
            f.write("debug-all\n")
            f.write(f"log-file {log_path}\n")
        os.chmod(conf_path, 0o600)

        # Tear down the user's persistent gpg-agent + scdaemon so no
        # stale PC/SC handles outlive our test. This only touches the
        # current user's processes; it will be auto-respawned next time
        # the user invokes gpg. Ignore failures.
        subprocess.run(
            ['pkill', '-u', os.environ.get('USER', ''), 'scdaemon'],
            capture_output=True,
        )
        subprocess.run(
            ['pkill', '-u', os.environ.get('USER', ''), 'gpg-agent'],
            capture_output=True,
        )

        # And kill any agent already running against our scratch
        # GNUPGHOME so the new scdaemon.conf is actually loaded on next
        # gpg invocation.
        subprocess.run(
            ['gpgconf', '--kill', 'all'],
            env=self.env,
            capture_output=True,
        )

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def delete_keys_by_email(self, email: str) -> bool:
        """Delete all GPG keys matching the given email."""
        try:
            result = subprocess.run(
                ['gpg', '--list-keys', '--with-colons', email],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return True

            fingerprints = []
            for line in result.stdout.split('\n'):
                if line.startswith('fpr:'):
                    parts = line.split(':')
                    if len(parts) >= 10:
                        fingerprints.append(parts[9])

            for fpr in fingerprints:
                subprocess.run(
                    ['gpg', '--batch', '--yes', '--delete-secret-keys', fpr],
                    env=self.env,
                    capture_output=True,
                    timeout=30,
                )
                subprocess.run(
                    ['gpg', '--batch', '--yes', '--delete-keys', fpr],
                    env=self.env,
                    capture_output=True,
                    timeout=30,
                )

            return True

        except Exception as e:
            print(f"Error during key cleanup: {e}")
            return False

    def factory_reset(self) -> bool:
        """Factory reset the card."""
        print("\n=== Factory Reset Card ===")

        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout,
        )

        try:
            child.expect('gpg/card>', timeout=30)
            child.sendline('admin')
            child.expect('gpg/card>')
            child.sendline('factory-reset')

            idx = child.expect(['Continue\\?', 'y/N', 'gpg/card>'], timeout=10)
            if idx in [0, 1]:
                child.sendline('y')
                try:
                    idx2 = child.expect(['Really', 'y/N', 'gpg/card>'], timeout=10)
                    if idx2 in [0, 1]:
                        child.sendline('yes')
                except pexpect.TIMEOUT:
                    pass

            child.expect('gpg/card>', timeout=30)
            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)

            print("Factory reset complete")
            return True

        except Exception as e:
            print(f"Reset failed: {e}")
            return False
        finally:
            child.close()

    def generate_p384_keys(
        self,
        user_name: str = "Test User",
        user_email: str = "test@example.com",
    ) -> bool:
        """Generate NIST P-384 keys on card using gpg --edit-card."""
        return self._generate_keys_via_keyattr(
            algo_choice='2',  # ECC
            extra_choice='4',  # NIST P-384
            label='NIST P-384',
            user_name=user_name,
            user_email=user_email,
        )

    def generate_rsa4096_keys(
        self,
        user_name: str = "Test User",
        user_email: str = "test@example.com",
    ) -> bool:
        """Generate RSA 4096 keys on card using gpg --edit-card."""
        return self._generate_keys_via_keyattr(
            algo_choice='1',  # RSA
            extra_choice='4096',  # 4096-bit modulus
            label='RSA 4096',
            user_name=user_name,
            user_email=user_email,
        )

    def _generate_keys_via_keyattr(
        self,
        algo_choice: str,
        extra_choice: str,
        label: str,
        user_name: str,
        user_email: str,
    ) -> bool:
        """Shared implementation: ``admin`` → ``key-attr`` → ``generate``.

        - For ECC (``algo_choice='2'``), ``extra_choice`` is the curve
          option number (e.g. ``'4'`` for P-384).
        - For RSA (``algo_choice='1'``), ``extra_choice`` is the bit
          length as a string (e.g. ``'4096'``).
        """
        print(f"\n=== Generate {label} Keys on Card ===")

        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --command-fd=0 --status-fd=1 --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout,
        )
        child.logfile = sys.stdout

        prompt_pattern = r'GET_LINE cardedit.prompt|gpg/card>'
        algo_pattern = r'GET_LINE cardedit.genkeys.algo|Your selection|selection'
        curve_pattern = r'GET_LINE keygen.curve|Your selection|curve'
        pin_pattern = r'GET_HIDDEN passphrase.enter'

        try:
            child.expect(prompt_pattern, timeout=30)

            child.sendline('admin')
            child.expect(prompt_pattern)

            child.sendline('key-attr')

            # For ECC (option 2), the next prompt is the curve menu
            # (`keygen.curve`). For RSA (option 1), gpg asks for the
            # number of bits (`keygen.size`).
            extra_pattern = (curve_pattern
                             if algo_choice == '2'
                             else r'GET_LINE cardedit\.genkeys\.size|GET_LINE keygen\.size|What keysize')

            for _slot in ('sig', 'enc', 'auth'):
                child.expect(algo_pattern, timeout=10)
                child.sendline(algo_choice)
                child.expect(extra_pattern, timeout=10)
                child.sendline(extra_choice)
                child.expect(pin_pattern, timeout=10)
                child.sendline(DEFAULT_ADMIN_PIN)

            child.expect(prompt_pattern, timeout=30)
            print(f"Key attributes set to {label}")

            child.sendline('generate')

            child.expect(
                ['GET_LINE cardedit.genkeys.backup_enc', 'backup', 'y/N'],
                timeout=15,
            )
            child.sendline('n')

            # After the backup question, gpg's generate flow asks for the
            # **admin PIN** (PW3) to set CHV-STATUS-1 (multi-sign mode).
            # Only then does it ask for the user PIN (PW1) to generate the
            # key material. Some cards may not need CHV-STATUS-1 set —
            # handle both orderings.
            idx = child.expect(
                [
                    r'GET_HIDDEN passphrase\.enter.*\r?\n',
                    'GET_LINE keygen.valid',
                    'Key is valid for',
                    'expire',
                ],
                timeout=15,
            )
            if idx == 0:
                # CHV-STATUS-1: admin PIN (PW3, 8+ chars).
                child.sendline(DEFAULT_ADMIN_PIN)
                # Then the user PIN for key generation.
                child.expect(pin_pattern, timeout=15)
                child.sendline(DEFAULT_USER_PIN)

            child.expect(
                ['GET_LINE keygen.valid', 'Key is valid for', 'expire', '0 ='],
                timeout=15,
            )
            child.sendline('0')

            child.expect(['GET_LINE keygen.name', 'Real name'], timeout=10)
            child.sendline(user_name)

            child.expect(['GET_LINE keygen.email', 'Email address'], timeout=10)
            child.sendline(user_email)

            child.expect(['GET_LINE keygen.comment', 'Comment'], timeout=10)
            child.sendline('')

            # Post-comment gpg needs the user PIN (PW1) to sign each
            # generated subkey's self-signature (``make_keysig_packet``).
            # It may also need the admin PIN (PW3) for PUT DATA of
            # fingerprints/timestamps. Dispatch each prompt to the right
            # PIN, and treat KEY_CREATED / KEY_NOT_CREATED as the terminal
            # states.
            key_created = False
            for _ in range(12):
                try:
                    idx = child.expect(
                        [
                            pin_pattern,
                            r'KEY_CREATED',
                            r'KEY_NOT_CREATED',
                            r'ERROR card_key_generate',
                            prompt_pattern,
                        ],
                        timeout=60,
                    )
                except pexpect.TIMEOUT:
                    break

                if idx == 0:
                    # Pick PIN based on what gpg just logged. Admin PIN is
                    # used for PUT DATA (fingerprint/date/status bytes) and
                    # CHV-STATUS. User PIN is used for make_keysig_packet
                    # (each self-signature). The clue is in ``child.before``.
                    before = child.before or ""
                    is_admin = ('Admin' in before
                                or 'admin' in before
                                or 'PW3' in before
                                or 'forced signature PIN' in before)
                    if is_admin:
                        child.sendline(DEFAULT_ADMIN_PIN)
                    else:
                        child.sendline(DEFAULT_USER_PIN)
                elif idx == 1:
                    print("Key created successfully!")
                    key_created = True
                    child.expect(prompt_pattern, timeout=30)
                    break
                elif idx in (2, 3):
                    print("Key NOT created (gpg reported failure).")
                    child.expect(prompt_pattern, timeout=30)
                    break
                else:
                    break

            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)

            if not key_created:
                print(f"{label} key generation did not produce KEY_CREATED")
                return False
            print(f"{label} key generation complete")
            return True

        except pexpect.TIMEOUT as e:
            print(f"Timeout: {e}")
            print(f"Before: {child.before}")
            return False
        except pexpect.EOF as e:
            print(f"EOF: {e}")
            return False
        finally:
            child.close()

    # ------------------------------------------------------------------
    # Crypto roundtrips
    # ------------------------------------------------------------------

    def test_sign_and_verify(self, email: str) -> bool:
        """Detached-sign a small file and verify."""
        print(f"\n=== Test Sign/Verify with {email} ===")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test message for signing\n")
            test_file = f.name

        sig_file = test_file + '.sig'

        try:
            result = subprocess.run(
                ['gpg', '--pinentry-mode', 'loopback', '--passphrase', DEFAULT_USER_PIN,
                 '-u', email, '--detach-sign', test_file],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                print(f"Signing failed: {result.stderr}")
                return False

            result = subprocess.run(
                ['gpg', '--verify', sig_file, test_file],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                print(f"Verification failed: {result.stderr}")
                return False

            print("Sign/Verify test passed")
            return True

        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)
            if os.path.exists(sig_file):
                os.unlink(sig_file)

    def test_encrypt_and_decrypt(self, email: str) -> bool:
        """Encrypt a tiny message to ``email`` and decrypt it back."""
        print(f"\n=== Test Encrypt/Decrypt with {email} ===")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            test_message = "Secret test message for encryption\n"
            f.write(test_message)
            test_file = f.name

        enc_file = test_file + '.gpg'
        dec_file = test_file + '.dec'

        try:
            result = subprocess.run(
                ['gpg', '--encrypt', '-r', email, '-o', enc_file, test_file],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                print(f"Encryption failed: {result.stderr}")
                return False

            result = subprocess.run(
                ['gpg', '--pinentry-mode', 'loopback', '--passphrase', DEFAULT_USER_PIN,
                 '-o', dec_file, '--decrypt', enc_file],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                print(f"Decryption failed: {result.stderr}")
                return False

            with open(dec_file, 'r') as fh:
                decrypted = fh.read()

            if decrypted != test_message:
                print(f"Content mismatch: expected '{test_message}', got '{decrypted}'")
                return False

            print("Encrypt/Decrypt test passed")
            return True

        finally:
            for f in [test_file, enc_file, dec_file]:
                if os.path.exists(f):
                    os.unlink(f)
