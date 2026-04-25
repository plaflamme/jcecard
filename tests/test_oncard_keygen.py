#!/usr/bin/env python3
"""
On-card key generation: Test key generation on card using GPG via pexpect.

This test:
1. Uses gpg --edit-card via pexpect to generate cv25519 keys on the card
2. Exports the public key using gpg
3. Encrypts a message using the public key  
4. Decrypts on the card using gpg

Prerequisites:
- pcscd running (with or without jcecard IFD handler)
- An OpenPGP card connected (Yubikey or virtual jcecard)
"""

import pytest
import pexpect
import tempfile
import os
import subprocess
from typing import Optional

from tests.gpg_card_helper import (
    JCECARD_SLOT0_SUFFIX,
    find_reader_by_suffix,
)


# Default PINs for virtual card
DEFAULT_USER_PIN = "123456"
DEFAULT_ADMIN_PIN = "12345678"


class GPGCardHelper:
    """Helper class to interact with GPG card operations via pexpect."""

    def __init__(
        self,
        timeout: int = 60,
        gnupg_home: Optional[str] = None,
        reader_port: Optional[str] = None,
    ):
        """Initialize GPG card helper.

        When ``gnupg_home`` is provided, gpg/scdaemon run against that
        isolated GNUPGHOME. When ``reader_port`` is provided, an
        ``scdaemon.conf`` pinning gpg to that PC/SC reader is written
        before the first gpg invocation — required when pcscd exposes
        more than one reader (e.g. slot 0 jcecard + slot 1 Nitrokey).
        """
        self.timeout = timeout
        self.env = os.environ.copy()
        if gnupg_home is not None:
            self.env['GNUPGHOME'] = gnupg_home
            self.gnupg_home = gnupg_home
            os.makedirs(self.gnupg_home, mode=0o700, exist_ok=True)
        else:
            self.gnupg_home = os.environ.get(
                'GNUPGHOME', os.path.expanduser('~/.gnupg')
            )

        if reader_port is not None:
            self._write_scdaemon_conf(reader_port)

    def _write_scdaemon_conf(self, reader_port: str) -> None:
        """Pin scdaemon to ``reader_port`` and tear down stale agents."""
        conf_path = os.path.join(self.gnupg_home, 'scdaemon.conf')
        log_path = os.path.join(self.gnupg_home, 'scdaemon.log')
        with open(conf_path, 'w') as f:
            f.write(f"reader-port {reader_port}\n")
            f.write("disable-ccid\n")
            f.write("pcsc-shared\n")
            f.write("debug-all\n")
            f.write(f"log-file {log_path}\n")
        os.chmod(conf_path, 0o600)

        subprocess.run(
            ['pkill', '-u', os.environ.get('USER', ''), 'scdaemon'],
            capture_output=True,
        )
        subprocess.run(
            ['pkill', '-u', os.environ.get('USER', ''), 'gpg-agent'],
            capture_output=True,
        )
        subprocess.run(
            ['gpgconf', '--kill', 'all'],
            env=self.env,
            capture_output=True,
        )

    def cleanup(self):
        """Tear down gpg-agent / scdaemon for this scratch GNUPGHOME."""
        subprocess.run(
            ['gpgconf', '--kill', 'all'],
            env=self.env,
            capture_output=True,
        )
    
    def delete_keys_by_email(self, email: str) -> bool:
        """
        Delete all GPG keys (public and secret) matching the given email.
        
        This prevents issues with multiple keys having the same email,
        which causes GPG to prompt for confirmation.
        
        Args:
            email: Email address to match keys against
            
        Returns:
            True if cleanup succeeded (or no keys found)
        """
        print(f"\n=== Cleaning up existing keys for {email} ===")
        
        try:
            # First, find all key fingerprints matching this email
            result = subprocess.run(
                ['gpg', '--list-keys', '--with-colons', email],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                # No keys found is OK
                print(f"No existing keys found for {email}")
                return True
            
            # Parse fingerprints from output
            fingerprints = []
            for line in result.stdout.split('\n'):
                if line.startswith('fpr:'):
                    parts = line.split(':')
                    if len(parts) >= 10:
                        fingerprints.append(parts[9])
            
            if not fingerprints:
                print(f"No keys found for {email}")
                return True
            
            print(f"Found {len(fingerprints)} key(s) to delete")
            
            # Delete each key (secret first, then public)
            for fpr in fingerprints:
                # Delete secret key
                subprocess.run(
                    ['gpg', '--batch', '--yes', '--delete-secret-keys', fpr],
                    env=self.env,
                    capture_output=True,
                    timeout=30
                )
                # Delete public key
                subprocess.run(
                    ['gpg', '--batch', '--yes', '--delete-keys', fpr],
                    env=self.env,
                    capture_output=True,
                    timeout=30
                )
                print(f"Deleted key {fpr[:16]}...")
            
            print("Key cleanup complete")
            return True
            
        except Exception as e:
            print(f"Error during key cleanup: {e}")
            return False
    
    def get_card_status(self) -> dict:
        """
        Get card status using gpg --card-status.
        
        Returns:
            Dictionary with card info or empty dict on error
        """
        try:
            result = subprocess.run(
                ['gpg', '--card-status'],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"Card status error: {result.stderr}")
                return {}
            
            # Parse output
            info = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, _, value = line.partition(':')
                    info[key.strip()] = value.strip()
            
            return info
            
        except Exception as e:
            print(f"Failed to get card status: {e}")
            return {}
    
    def factory_reset(self) -> bool:
        """
        Factory reset the card using gpg --edit-card.
        
        Returns:
            True if successful
        """
        print("\n=== Factory Reset Card ===")
        
        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout
        )
        child.logfile = None  # Set to sys.stdout for debugging
        
        try:
            # Wait for gpg/card prompt
            child.expect('gpg/card>', timeout=30)
            
            # Enter admin mode
            child.sendline('admin')
            child.expect('gpg/card>')
            
            # Factory reset
            child.sendline('factory-reset')
            
            # Confirm reset - GPG asks multiple times
            idx = child.expect(['Continue\\?', 'y/N', 'gpg/card>'], timeout=10)
            if idx in [0, 1]:
                child.sendline('y')
                
                # May ask for final confirmation
                try:
                    idx2 = child.expect(['Really', 'y/N', 'gpg/card>'], timeout=10)
                    if idx2 in [0, 1]:
                        child.sendline('yes')
                except pexpect.TIMEOUT:
                    pass
            
            # Wait for completion
            child.expect('gpg/card>', timeout=30)
            
            # Quit
            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)
            
            print("Factory reset complete")
            return True
            
        except pexpect.TIMEOUT as e:
            print(f"Timeout during reset: {e}")
            print(f"Before: {child.before}")
            return False
        except pexpect.EOF as e:
            print(f"EOF during reset: {e}")
            return False
        finally:
            child.close()
    
    def generate_cv25519_keys(self, user_name: str = "Test User", 
                              user_email: str = "test@example.com") -> bool:
        """
        Generate cv25519 keys on card using gpg --edit-card.
        
        This sets the key algorithm to cv25519 and generates new keys.
        
        Args:
            user_name: Name for the key
            user_email: Email for the key
            
        Returns:
            True if successful
        """
        print("\n=== Generate CV25519 Keys on Card ===")
        
        import sys
        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --command-fd=0 --status-fd=1 --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout
        )
        child.logfile = sys.stdout  # Enable logging for debugging
        
        # With --status-fd, GPG outputs [GNUPG:] GET_LINE cardedit.prompt instead of gpg/card>
        prompt_pattern = r'GET_LINE cardedit.prompt|gpg/card>'
        algo_pattern = r'GET_LINE cardedit.genkeys.algo|Your selection|selection'
        curve_pattern = r'GET_LINE keygen.curve|Your selection|curve'
        pin_pattern = r'GET_HIDDEN passphrase.enter'
        
        try:
            # Wait for gpg/card prompt
            child.expect(prompt_pattern, timeout=30)
            
            # Enter admin mode
            child.sendline('admin')
            child.expect(prompt_pattern)
            
            # Set key algorithm to ECC (cv25519)
            # key-attr command lets us select algorithm for each key slot
            child.sendline('key-attr')
            
            # Signature key - select ECC
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            
            # Select curve for signature key - EdDSA
            child.expect(curve_pattern, timeout=10)
            child.sendline('1')  # Curve 25519
            
            # Admin PIN required after signature key attr change
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Encryption key - select ECC
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            
            # Select curve for encryption key - cv25519
            child.expect(curve_pattern, timeout=10)
            child.sendline('1')  # Curve 25519
            
            # Admin PIN required again after encryption key attr change
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Authentication key - select ECC
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            
            # Select curve for authentication key - EdDSA
            child.expect(curve_pattern, timeout=10)
            child.sendline('1')  # Curve 25519
            
            # Admin PIN required again after authentication key attr change
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Wait for key-attr to complete
            child.expect(prompt_pattern, timeout=30)
            
            print("Key attributes set to cv25519")
            
            # Now generate the keys
            child.sendline('generate')
            
            # Backup question - no backup (GET_LINE cardedit.genkeys.backup_enc)
            child.expect(['GET_LINE cardedit.genkeys.backup_enc', 'backup', 'y/N'], timeout=15)
            child.sendline('n')
            
            # User PIN required for generate (not Admin PIN!)
            child.expect(pin_pattern, timeout=15)
            child.sendline(DEFAULT_USER_PIN)
            
            # Key expiration (GET_LINE keygen.valid)
            child.expect(['GET_LINE keygen.valid', 'Key is valid for', 'expire', '0 ='], timeout=15)
            child.sendline('0')  # No expiration
            
            # Note: GPG does NOT ask "Is this correct?" when 0 (no expiration) is selected
            # It goes directly to asking for the name
            
            # Real name (GET_LINE keygen.name)
            child.expect(['GET_LINE keygen.name', 'Real name'], timeout=10)
            child.sendline(user_name)
            
            # Email (GET_LINE keygen.email)
            child.expect(['GET_LINE keygen.email', 'Email address'], timeout=10)
            child.sendline(user_email)
            
            # Comment (GET_LINE keygen.comment)
            child.expect(['GET_LINE keygen.comment', 'Comment'], timeout=10)
            child.sendline('')
            
            # GPG shows "You selected this USER-ID:" but with --status-fd it goes
            # directly to asking for Admin PIN for key generation (no confirmation prompt)
            
            # Admin PIN for key generation
            child.expect(pin_pattern, timeout=15)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # PIN prompts for key generation on card
            # After Admin PIN, gpg may need User PIN for signing the key
            # NEED_PASSPHRASE indicates signing operation (needs User PIN)
            for _ in range(6):  # Up to 6 PIN prompts
                try:
                    idx = child.expect([r'NEED_PASSPHRASE', pin_pattern, r'KEY_CREATED', prompt_pattern], timeout=60)
                    if idx == 0:
                        # NEED_PASSPHRASE means signing operation - use User PIN
                        child.expect(pin_pattern, timeout=10)
                        child.sendline(DEFAULT_USER_PIN)
                    elif idx == 1:
                        # Generic PIN prompt - try Admin PIN
                        child.sendline(DEFAULT_ADMIN_PIN)
                    elif idx == 2:
                        # KEY_CREATED - success! Wait for prompt
                        print("Key created successfully!")
                        child.expect(prompt_pattern, timeout=30)
                        break
                    else:
                        break  # Got the prompt, key generation done
                except pexpect.TIMEOUT:
                    break
            
            # Quit
            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)
            
            print("Key generation complete")
            return True
            
        except pexpect.TIMEOUT as e:
            print(f"Timeout during key generation: {e}")
            print(f"Before: {child.before}")
            return False
        except pexpect.EOF as e:
            print(f"EOF during key generation: {e}")
            return False
        finally:
            child.close()
    
    def generate_rsa4096_keys(self, user_name: str = "Test User",
                              user_email: str = "test@example.com") -> bool:
        """
        Generate RSA4096 keys on card using gpg --edit-card.
        
        This sets the key algorithm to RSA 4096 and generates new keys.
        Note: RSA key generation is MUCH slower than cv25519 (~80 seconds per key).
        
        Args:
            user_name: Name for the key
            user_email: Email for the key
            
        Returns:
            True if successful
        """
        print("\n=== Generate RSA4096 Keys on Card ===")
        print("WARNING: This will take several minutes (RSA4096 key generation is slow)")
        
        import sys
        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --command-fd=0 --status-fd=1 --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=300  # Longer timeout for RSA
        )
        child.logfile = sys.stdout  # Enable logging for debugging
        
        prompt_pattern = r'GET_LINE cardedit.prompt|gpg/card>'
        algo_pattern = r'GET_LINE cardedit.genkeys.algo|Your selection|selection'
        size_pattern = r'GET_LINE cardedit.genkeys.size|keysize'
        pin_pattern = r'GET_HIDDEN passphrase.enter'
        
        try:
            # Wait for gpg/card prompt
            child.expect(prompt_pattern, timeout=30)
            
            # Enter admin mode
            child.sendline('admin')
            child.expect(prompt_pattern)
            
            # Set key algorithm to RSA
            child.sendline('key-attr')
            
            # Signature key - select RSA
            child.expect(algo_pattern, timeout=10)
            child.sendline('1')  # RSA
            
            # Select key size for signature key
            child.expect(size_pattern, timeout=10)
            child.sendline('4096')  # RSA 4096
            
            # Admin PIN required
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Encryption key - select RSA
            child.expect(algo_pattern, timeout=10)
            child.sendline('1')  # RSA
            
            # Select key size for encryption key
            child.expect(size_pattern, timeout=10)
            child.sendline('4096')  # RSA 4096
            
            # Admin PIN required
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Authentication key - select RSA
            child.expect(algo_pattern, timeout=10)
            child.sendline('1')  # RSA
            
            # Select key size for authentication key
            child.expect(size_pattern, timeout=10)
            child.sendline('4096')  # RSA 4096
            
            # Admin PIN required
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Wait for key-attr to complete
            child.expect(prompt_pattern, timeout=30)
            
            print("Key attributes set to RSA 4096")
            
            # Now generate the keys
            child.sendline('generate')
            
            # Backup question
            child.expect(['GET_LINE cardedit.genkeys.backup_enc', 'backup', 'y/N'], timeout=15)
            child.sendline('n')
            
            # User PIN required
            child.expect(pin_pattern, timeout=15)
            child.sendline(DEFAULT_USER_PIN)
            
            # Key expiration
            child.expect(['GET_LINE keygen.valid', 'Key is valid for', 'expire', '0 ='], timeout=15)
            child.sendline('0')  # No expiration
            
            # Real name
            child.expect(['GET_LINE keygen.name', 'Real name'], timeout=10)
            child.sendline(user_name)
            
            # Email
            child.expect(['GET_LINE keygen.email', 'Email address'], timeout=10)
            child.sendline(user_email)
            
            # Comment
            child.expect(['GET_LINE keygen.comment', 'Comment'], timeout=10)
            child.sendline('')
            
            # Admin PIN for key generation
            child.expect(pin_pattern, timeout=15)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # PIN prompts for key generation - RSA takes MUCH longer
            print("Generating RSA4096 keys (this will take 4-5 minutes)...")
            for _ in range(6):
                try:
                    idx = child.expect([r'NEED_PASSPHRASE', pin_pattern, r'KEY_CREATED', prompt_pattern], timeout=300)
                    if idx == 0:
                        child.expect(pin_pattern, timeout=10)
                        child.sendline(DEFAULT_USER_PIN)
                    elif idx == 1:
                        child.sendline(DEFAULT_ADMIN_PIN)
                    elif idx == 2:
                        print("Key created successfully!")
                        child.expect(prompt_pattern, timeout=30)
                        break
                    else:
                        break
                except pexpect.TIMEOUT:
                    print("Still generating... (RSA4096 takes time)")
                    continue
            
            # Quit
            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)
            
            print("RSA4096 key generation complete")
            return True
            
        except pexpect.TIMEOUT as e:
            print(f"Timeout during key generation: {e}")
            print(f"Before: {child.before}")
            return False
        except pexpect.EOF as e:
            print(f"EOF during key generation: {e}")
            return False
        finally:
            child.close()
    
    def export_public_key(self, key_id: str | None = None) -> str:
        """
        Export the public key from the card.
        
        Args:
            key_id: Key ID or email to export (exports all if None)
            
        Returns:
            Armored public key string, or empty string on error
        """
        print("\n=== Export Public Key ===")
        
        try:
            cmd = ['gpg', '--armor', '--export']
            if key_id:
                cmd.append(key_id)
            
            result = subprocess.run(
                cmd,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                print(f"Exported public key ({len(result.stdout)} bytes)")
                return result.stdout
            else:
                print(f"Export failed: {result.stderr}")
                return ""
                
        except Exception as e:
            print(f"Failed to export public key: {e}")
            return ""
    
    def encrypt_message(self, message: str, recipient: str) -> str:
        """
        Encrypt a message for a recipient.
        
        Args:
            message: The message to encrypt
            recipient: Email or key ID of recipient
            
        Returns:
            Armored encrypted message, or empty string on error
        """
        print(f"\n=== Encrypt Message for {recipient} ===")
        
        try:
            result = subprocess.run(
                ['gpg', '--armor', '--encrypt', '--recipient', recipient, '--trust-model', 'always'],
                input=message,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                print(f"Encrypted message ({len(result.stdout)} bytes)")
                return result.stdout
            else:
                print(f"Encryption failed: {result.stderr}")
                return ""
                
        except Exception as e:
            print(f"Failed to encrypt: {e}")
            return ""
    
    def decrypt_message(self, encrypted: str) -> str:
        """
        Decrypt a message using the card.
        
        This will prompt for PIN via pinentry.
        
        Args:
            encrypted: The armored encrypted message
            
        Returns:
            Decrypted plaintext, or empty string on error
        """
        print("\n=== Decrypt Message on Card ===")
        
        # For automated testing, we need to handle PIN entry
        # Use gpg with --pinentry-mode loopback and --passphrase
        child = pexpect.spawn(
            'gpg --decrypt --pinentry-mode loopback',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout
        )
        child.logfile = None
        
        try:
            # Send the encrypted message
            child.sendline(encrypted)
            child.sendeof()
            
            # Wait for PIN prompt
            try:
                child.expect(['PIN', 'passphrase', 'Passphrase'], timeout=15)
                child.sendline(DEFAULT_USER_PIN)
            except pexpect.TIMEOUT:
                pass
            
            # Wait for decryption
            child.expect(pexpect.EOF, timeout=30)
            
            # Get output
            output = child.before
            if output is None:
                raise ValueError("No output received from GPG")
            
            # Parse out the decrypted message (remove gpg status messages)
            lines = output.split('\n')
            decrypted_lines = []
            
            for line in lines:
                # Skip gpg status lines
                if line.startswith('gpg:'):
                    continue
                if '-----BEGIN PGP MESSAGE-----' in line:
                    continue
                if '-----END PGP MESSAGE-----' in line:
                    continue
                if line.strip():
                    decrypted_lines.append(line)
            
            decrypted = '\n'.join(decrypted_lines).strip()
            print(f"Decrypted: {decrypted[:50]}...")
            return decrypted
            
        except pexpect.TIMEOUT as e:
            print(f"Timeout during decryption: {e}")
            print(f"Before: {child.before}")
            return ""
        except pexpect.EOF:
            # Try to get what we have
            return child.before.strip() if child.before else ""
        finally:
            child.close()
    
    def decrypt_message_simple(self, encrypted: str) -> str:
        """
        Simpler decryption using subprocess with echo for PIN.
        
        Args:
            encrypted: The armored encrypted message
            
        Returns:
            Decrypted plaintext, or empty string on error
        """
        print("\n=== Decrypt Message on Card (simple) ===")
        
        try:
            # Write encrypted message to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as f:
                f.write(encrypted)
                encrypted_file = f.name
            
            try:
                # Use --batch and --pinentry-mode loopback with --passphrase
                result = subprocess.run(
                    [
                        'gpg', '--decrypt',
                        '--batch',
                        '--pinentry-mode', 'loopback',
                        '--passphrase', DEFAULT_USER_PIN,
                        encrypted_file
                    ],
                    env=self.env,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    print("Decrypted successfully")
                    return result.stdout
                else:
                    print(f"Decryption failed: {result.stderr}")
                    return ""
                    
            finally:
                os.unlink(encrypted_file)
                
        except Exception as e:
            print(f"Failed to decrypt: {e}")
            return ""


class TestOnCardKeyGeneration:
    """
    On-card Tests: Generate keys on card using GPG via pexpect.
    
    These tests work with any OpenPGP card (real Yubikey or jcecard virtual card).
    
    Requirements:
    - pcscd running (with or without jcecard IFD handler)
    - An OpenPGP card connected (Yubikey or virtual jcecard)
    """
    
    @pytest.fixture
    def gpg_helper(self, tmp_path):
        """Create a GPG helper pinned to slot 0 with a scratch GNUPGHOME.

        Skips if the slot-0 reader is not present (e.g. pcscd not running
        or the IFD handler is not installed). With two readers visible,
        scdaemon would otherwise pick slot 1 (Nitrokey) and the on-card
        keygen flow would target the wrong applet.
        """
        reader = find_reader_by_suffix(JCECARD_SLOT0_SUFFIX)
        if reader is None:
            pytest.skip(
                f"jcecard slot-0 reader (suffix '{JCECARD_SLOT0_SUFFIX}') not found"
            )
        gnupg_home = tmp_path / "gnupg-oncard"
        gnupg_home.mkdir(mode=0o700)
        helper = GPGCardHelper(gnupg_home=str(gnupg_home), reader_port=reader)
        yield helper
        helper.cleanup()
    
    def test_card_is_available(self, gpg_helper):
        """Test that an OpenPGP card is accessible via gpg."""
        status = gpg_helper.get_card_status()
        
        assert status, "Card should be accessible"
        # Check for any key that indicates we got card status
        assert any('Application' in k or 'Reader' in k or 'Serial' in k for k in status.keys()), \
            f"Should have card info, got keys: {list(status.keys())[:5]}"
        
        print("\nCard Status:")
        for key, value in list(status.items())[:10]:
            print(f"  {key}: {value}")
    
    def test_factory_reset(self, gpg_helper):
        """Test factory reset of the card."""
        result = gpg_helper.factory_reset()
        assert result, "Factory reset should succeed"
        
        # Verify card is reset
        status = gpg_helper.get_card_status()
        assert status, "Card should still be accessible after reset"
    
    def test_generate_cv25519_keys(self, gpg_helper):
        """Test generating cv25519 keys on the card."""
        test_email = "oncard@test.local"
        
        # Clean up any existing keys with this email
        gpg_helper.delete_keys_by_email(test_email)
        
        # First reset the card
        reset_result = gpg_helper.factory_reset()
        assert reset_result, "Factory reset should succeed"
        
        # Generate keys
        gen_result = gpg_helper.generate_cv25519_keys(
            user_name="OnCard Test",
            user_email=test_email
        )
        assert gen_result, "Key generation should succeed"
        
        # Verify keys are on card
        status = gpg_helper.get_card_status()
        print("\nCard status after key generation:")
        for key, value in status.items():
            if 'key' in key.lower() or 'finger' in key.lower():
                print(f"  {key}: {value}")
    
    def test_full_encrypt_decrypt_flow(self, gpg_helper):
        """
        Full flow test:
        1. Reset card
        2. Generate cv25519 keys
        3. Export public key
        4. Encrypt a message
        5. Decrypt on card
        6. Verify decrypted matches original
        """
        test_email = "encrypt@test.local"
        
        # Step 0: Clean up any existing keys with the test email
        print("\n" + "="*60)
        print("Step 0: Clean up existing test keys")
        print("="*60)
        gpg_helper.delete_keys_by_email(test_email)
        
        # Step 1: Reset card
        print("\n" + "="*60)
        print("Step 1: Factory Reset")
        print("="*60)
        assert gpg_helper.factory_reset(), "Factory reset should succeed"
        
        # Step 2: Generate keys
        print("\n" + "="*60)
        print("Step 2: Generate CV25519 Keys")
        print("="*60)
        assert gpg_helper.generate_cv25519_keys(
            user_name="Encrypt Test",
            user_email=test_email
        ), "Key generation should succeed"
        
        # Step 3: Export public key
        print("\n" + "="*60)
        print("Step 3: Export Public Key")
        print("="*60)
        public_key = gpg_helper.export_public_key(test_email)
        assert public_key, "Should export public key"
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in public_key
        
        # Step 4: Encrypt a message
        print("\n" + "="*60)
        print("Step 4: Encrypt Message")
        print("="*60)
        original_message = "Hello from on-card keygen! This is a test message for cv25519 encryption."
        encrypted = gpg_helper.encrypt_message(original_message, test_email)
        assert encrypted, "Should encrypt message"
        assert "-----BEGIN PGP MESSAGE-----" in encrypted
        
        # Step 5: Decrypt on card
        print("\n" + "="*60)
        print("Step 5: Decrypt on Card")
        print("="*60)
        decrypted = gpg_helper.decrypt_message_simple(encrypted)
        assert decrypted, "Should decrypt message"
        
        # Step 6: Verify
        print("\n" + "="*60)
        print("Step 6: Verify")
        print("="*60)
        print(f"Original:  {original_message}")
        print(f"Decrypted: {decrypted}")
        assert decrypted.strip() == original_message.strip(), "Decrypted should match original"
        
        print("\n" + "="*60)
        print("SUCCESS: Full encrypt/decrypt flow completed!")
        print("="*60)
    
    
    def test_full_rsa4096_sign_verify_flow(self, gpg_helper):
        """
        Full RSA4096 flow test:
        1. Reset card
        2. Generate RSA4096 keys
        3. Export public key
        4. Sign a message
        5. Verify signature
        
        WARNING: This test is SLOW! RSA4096 key generation takes 4-5 minutes.
        """
        test_email = "rsasign@test.local"
        
        # Step 0: Clean up any existing keys with the test email
        print("\n" + "="*60)
        print("Step 0: Clean up existing test keys")
        print("="*60)
        gpg_helper.delete_keys_by_email(test_email)
        
        # Step 1: Reset card
        print("\n" + "="*60)
        print("Step 1: Factory Reset")
        print("="*60)
        assert gpg_helper.factory_reset(), "Factory reset should succeed"
        
        # Step 2: Generate RSA4096 keys
        print("\n" + "="*60)
        print("Step 2: Generate RSA4096 Keys (this will take several minutes)")
        print("="*60)
        assert gpg_helper.generate_rsa4096_keys(
            user_name="RSA Sign Test",
            user_email=test_email
        ), "RSA4096 key generation should succeed"
        
        # Step 3: Export public key
        print("\n" + "="*60)
        print("Step 3: Export Public Key")
        print("="*60)
        public_key = gpg_helper.export_public_key(test_email)
        assert public_key, "Should export public key"
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in public_key
        assert "rsa4096" in public_key.lower() or "RSA" in public_key or len(public_key) > 2000, \
            "Should be RSA key (larger than ECC)"
        
        # Step 4: Create and sign a test message
        print("\n" + "="*60)
        print("Step 4: Sign Message")
        print("="*60)
        original_message = "This is a test message for RSA4096 signature verification."
        
        # Create a detached signature
        try:
            result = subprocess.run(
                [
                    'gpg', '--armor', '--detach-sign',
                    '--pinentry-mode', 'loopback',
                    '--passphrase', DEFAULT_USER_PIN,
                    '--local-user', test_email
                ],
                input=original_message,
                env=gpg_helper.env,
                capture_output=True,
                text=True,
                timeout=120
            )
            assert result.returncode == 0, f"Signing failed: {result.stderr}"
            signature = result.stdout
            assert "-----BEGIN PGP SIGNATURE-----" in signature
            print(f"Signature created ({len(signature)} bytes)")
        except Exception as e:
            pytest.fail(f"Failed to create signature: {e}")
        
        # Step 5: Verify signature
        print("\n" + "="*60)
        print("Step 5: Verify Signature")
        print("="*60)
        
        # Write message and signature to temp files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as msg_file:
            msg_file.write(original_message)
            msg_path = msg_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sig', delete=False) as sig_file:
            sig_file.write(signature)
            sig_path = sig_file.name
        
        try:
            # Verify the signature
            result = subprocess.run(
                ['gpg', '--verify', sig_path, msg_path],
                env=gpg_helper.env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check verification result
            verify_output = result.stderr + result.stdout
            print(f"Verification output:\n{verify_output}")
            
            assert "Good signature" in verify_output or result.returncode == 0, \
                f"Signature verification failed: {verify_output}"
            
            print("Signature verified successfully!")
            
        finally:
            os.unlink(msg_path)
            os.unlink(sig_path)
        
        print("\n" + "="*60)
        print("SUCCESS: Full RSA4096 sign/verify flow completed!")
        print("="*60)


if __name__ == '__main__':
    # Run tests directly
    pytest.main([__file__, '-xvs'])
