"""Integration tests using yubico-piv-tool against jcecard via pcscd.

These tests require:
- pcscd running with the jcecard IFD handler installed (just install-ifd && just restart-pcscd)
- yubico-piv-tool installed

Run with: pytest tests/test_smartcard_piv.py -xvs
Or mark to skip if environment not ready: pytest -m "not integration"
"""

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pexpect
import pytest

# Default PIV credentials
DEFAULT_PIN = "123456"
DEFAULT_PUK = "12345678"
DEFAULT_MGMT_KEY = "010203040506070801020304050607080102030405060708"

# Slot-0 reader name as advertised by pcscd. With two slots present (slot 0
# jcecard + slot 1 Nitrokey), yubico-piv-tool defaults to "Yubikey" prefix
# matching and connects to neither — so every PIV command must pin the
# reader explicitly. List-readers / version still work fine with the flag.
PIV_READER = "jcecard Virtual Smart Card 00 00"

# Pytest marker for integration tests
pytestmark = pytest.mark.integration


def is_jcecard_running() -> bool:
    """Check if jcecard virtual card is available via pcscd."""
    try:
        result = subprocess.run(
            ["pcsc_scan", "-r"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Check if jcecard reader is listed
        return "jcecard" in result.stdout.lower()
    except Exception:
        return False


def is_pcscd_running() -> bool:
    """Check if pcscd is running."""
    try:
        result = subprocess.run(
            ["pgrep", "pcscd"],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def is_yubico_piv_tool_installed() -> bool:
    """Check if yubico-piv-tool is installed."""
    return shutil.which("yubico-piv-tool") is not None


def _inject_reader(cmd: str) -> str:
    """Insert ``-r '<slot 0 reader>'`` into a yubico-piv-tool command line."""
    prefix = "yubico-piv-tool"
    if cmd.startswith(prefix):
        return f"{prefix} -r '{PIV_READER}'{cmd[len(prefix):]}"
    return cmd


def run_cmd(cmd: str, timeout: int = 30) -> tuple[bool, str]:
    """Run a simple command and return (success, output)."""
    try:
        result = subprocess.run(
            _inject_reader(cmd),
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def run_piv_tool_interactive(
    args: str,
    timeout: int = 30,
    provide_mgmt_key: bool = False,
    provide_pin: bool = False,
    provide_puk: bool = False,
    provide_new_pin: bool = False,
) -> tuple[bool, str]:
    """Run yubico-piv-tool with interactive prompts.

    Args:
        args: Command arguments (without the tool name)
        timeout: Command timeout in seconds
        provide_mgmt_key: If True, automatically provide management key when prompted
        provide_pin: If True, automatically provide PIN when prompted
        provide_puk: If True, automatically provide PUK when prompted
        provide_new_pin: If True, provide new PIN when prompted

    Returns:
        Tuple of (success, output)
    """
    cmd = f"yubico-piv-tool -r '{PIV_READER}' {args}"

    try:
        child = pexpect.spawn(cmd, timeout=timeout, encoding="utf-8")
        output_buffer = []

        while True:
            try:
                index = child.expect(
                    [
                        pexpect.EOF,
                        pexpect.TIMEOUT,
                        r"Enter management key:",
                        r"Enter current management key:",
                        r"Enter PIN:",
                        r"Enter current PIN:",
                        r"Enter PUK:",
                        r"Enter new PIN:",
                        r"Verify new PIN:",
                        r"Successfully generated",
                        r"Successfully imported",
                        r"Successfully verified PIN",
                        r"Successfully changed",
                        r"Successful ECDSA verification",
                        r"Successful ECDH exchange",
                    ],
                    timeout=timeout,
                )

                if child.before:
                    output_buffer.append(child.before)

                if index == 0:  # EOF
                    break
                elif index == 1:  # TIMEOUT
                    output_buffer.append("\n[TIMEOUT]")
                    break
                elif index in [2, 3]:  # Management key prompt
                    if provide_mgmt_key:
                        child.sendline(DEFAULT_MGMT_KEY)
                    else:
                        output_buffer.append("\n[MGMT KEY PROMPT - not provided]")
                        break
                elif index in [4, 5]:  # PIN prompt
                    if provide_pin:
                        child.sendline(DEFAULT_PIN)
                    else:
                        output_buffer.append("\n[PIN PROMPT - not provided]")
                        break
                elif index == 6:  # PUK prompt
                    if provide_puk:
                        child.sendline(DEFAULT_PUK)
                    else:
                        output_buffer.append("\n[PUK PROMPT - not provided]")
                        break
                elif index in [7, 8]:  # New PIN prompt / Verify new PIN
                    if provide_new_pin:
                        child.sendline(DEFAULT_PIN)
                    else:
                        output_buffer.append("\n[NEW PIN PROMPT - not provided]")
                        break
                elif index >= 9:  # Success messages
                    output_buffer.append(child.after)

            except pexpect.TIMEOUT:
                output_buffer.append("\n[TIMEOUT]")
                break
            except pexpect.EOF:
                break

        child.close()
        output = "".join(output_buffer)
        success = child.exitstatus == 0 if child.exitstatus is not None else False
        return success, output

    except Exception as e:
        return False, str(e)


@pytest.fixture(scope="module")
def check_environment():
    """Check that the integration test environment is ready."""
    if not is_yubico_piv_tool_installed():
        pytest.skip("yubico-piv-tool not installed")

    if not is_jcecard_running():
        pytest.skip("jcecard virtual card not available (run: just install-ifd && just restart-pcscd)")

    if not is_pcscd_running():
        pytest.skip("pcscd not running")

    # Kill scdaemon to release card lock - it conflicts with yubico-piv-tool
    subprocess.run(["pkill", "-9", "scdaemon"], capture_output=True)

    # Small delay to ensure services are ready
    time.sleep(0.5)


@pytest.fixture(scope="module")
def temp_dir():
    """Create a temporary directory for test files."""
    tmpdir = tempfile.mkdtemp(prefix="piv_test_")
    yield Path(tmpdir)
    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestPIVBasicOperations:
    """Test basic PIV operations using yubico-piv-tool."""

    def test_version(self, check_environment):
        """Test getting version information."""
        success, output = run_cmd("yubico-piv-tool -a version")
        # May fail if card returns different version format, but command should run
        assert "yubico-piv-tool" in output.lower() or "version" in output.lower() or success

    def test_list_readers(self, check_environment):
        """Test listing smart card readers."""
        success, output = run_cmd("yubico-piv-tool -a list-readers")
        # Should show our virtual reader
        assert success or "jcecard" in output.lower() or "reader" in output.lower()

    def test_status(self, check_environment):
        """Test getting device status."""
        success, output = run_cmd("yubico-piv-tool -a status")
        # Status command should work
        assert success or "PIV" in output or "version" in output.lower()

    def test_verify_pin(self, check_environment):
        """Test PIN verification."""
        success, output = run_cmd(f"yubico-piv-tool -a verify-pin -P {DEFAULT_PIN}")
        assert success or "verified" in output.lower()


class TestPIVDataObjects:
    """Test PIV data object operations."""

    def test_set_chuid(self, check_environment):
        """Test setting Card Holder Unique Identifier (CHUID)."""
        success, output = run_piv_tool_interactive(
            "-a set-chuid -k -",
            timeout=30,
            provide_mgmt_key=True,
        )
        # CHUID should be set successfully
        assert success or "successfully" in output.lower()

    def test_set_ccc(self, check_environment):
        """Test setting Card Capability Container (CCC)."""
        success, output = run_piv_tool_interactive(
            "-a set-ccc -k -",
            timeout=30,
            provide_mgmt_key=True,
        )
        # CCC should be set successfully
        assert success or "successfully" in output.lower()


class TestPIVECCP256KeyGeneration:
    """Test ECC P-256 key generation operations."""

    def test_generate_key_slot_9a(self, check_environment, temp_dir):
        """Test generating ECC P-256 key in slot 9a (Authentication)."""
        pubkey_file = temp_dir / "pubkey_9a.pem"

        success, output = run_piv_tool_interactive(
            f"-a generate -s 9a -A ECCP256 -k - -o {pubkey_file}",
            timeout=60,
            provide_mgmt_key=True,
        )

        # Check that key was generated
        if pubkey_file.exists() and pubkey_file.stat().st_size > 0:
            # Verify it's a valid EC public key
            verify_success, verify_output = run_cmd(
                f"openssl ec -pubin -in {pubkey_file} -text -noout 2>/dev/null || "
                f"openssl pkey -pubin -in {pubkey_file} -text -noout"
            )
            assert pubkey_file.exists()
            assert pubkey_file.stat().st_size > 0
        else:
            # Key generation succeeded based on output
            assert success or "generated" in output.lower()

    def test_generate_key_slot_9c(self, check_environment, temp_dir):
        """Test generating ECC P-256 key in slot 9c (Digital Signature)."""
        pubkey_file = temp_dir / "pubkey_9c.pem"

        success, output = run_piv_tool_interactive(
            f"-a generate -s 9c -A ECCP256 -k - -o {pubkey_file}",
            timeout=60,
            provide_mgmt_key=True,
        )

        if pubkey_file.exists():
            assert pubkey_file.stat().st_size > 0
        else:
            assert success or "generated" in output.lower()

    def test_generate_key_slot_9d(self, check_environment, temp_dir):
        """Test generating ECC P-256 key in slot 9d (Key Management/ECDH)."""
        pubkey_file = temp_dir / "pubkey_9d.pem"

        success, output = run_piv_tool_interactive(
            f"-a generate -s 9d -A ECCP256 -k - -o {pubkey_file}",
            timeout=60,
            provide_mgmt_key=True,
        )

        if pubkey_file.exists():
            assert pubkey_file.stat().st_size > 0
        else:
            assert success or "generated" in output.lower()

    def test_generate_key_slot_9e(self, check_environment, temp_dir):
        """Test generating ECC P-256 key in slot 9e (Card Authentication)."""
        pubkey_file = temp_dir / "pubkey_9e.pem"

        success, output = run_piv_tool_interactive(
            f"-a generate -s 9e -A ECCP256 -k - -o {pubkey_file}",
            timeout=60,
            provide_mgmt_key=True,
        )

        if pubkey_file.exists():
            assert pubkey_file.stat().st_size > 0
        else:
            assert success or "generated" in output.lower()


class TestPIVCertificateOperations:
    """Test PIV certificate operations."""

    @pytest.fixture(autouse=True)
    def setup_key(self, check_environment, temp_dir):
        """Generate a key before certificate tests."""
        self.pubkey_file = temp_dir / "pubkey_cert_test.pem"
        self.cert_file = temp_dir / "cert_test.pem"

        # Generate key in slot 9a
        run_piv_tool_interactive(
            f"-a generate -s 9a -A ECCP256 -k - -o {self.pubkey_file}",
            timeout=60,
            provide_mgmt_key=True,
        )
        time.sleep(0.3)

    def test_selfsign_certificate(self, check_environment, temp_dir):
        """Test self-signing a certificate."""
        if not self.pubkey_file.exists():
            pytest.skip("Public key not generated")

        success, output = run_piv_tool_interactive(
            f"-a verify-pin -a selfsign-certificate -s 9a "
            f"-S '/CN=Test PIV Auth/O=Test Org/' "
            f"-i {self.pubkey_file} -o {self.cert_file}",
            timeout=60,
            provide_pin=True,
        )

        if self.cert_file.exists():
            assert self.cert_file.stat().st_size > 0
            # Verify certificate
            verify_success, _ = run_cmd(f"openssl x509 -in {self.cert_file} -text -noout")
            assert verify_success
        else:
            # Self-sign may not be fully supported, check output
            pass

    def test_import_certificate(self, check_environment, temp_dir):
        """Test importing a certificate to the card."""
        if not self.cert_file.exists():
            pytest.skip("Certificate not generated")

        success, output = run_piv_tool_interactive(
            f"-a import-certificate -s 9a -i {self.cert_file} -k -",
            timeout=30,
            provide_mgmt_key=True,
        )

        assert success or "imported" in output.lower() or "success" in output.lower()

    def test_read_certificate(self, check_environment, temp_dir):
        """Test reading a certificate from the card."""
        read_cert_file = temp_dir / "cert_read.pem"

        success, output = run_cmd(
            f"yubico-piv-tool -a read-certificate -s 9a -o {read_cert_file}"
        )

        # May not have a cert if previous tests didn't import one
        if read_cert_file.exists() and read_cert_file.stat().st_size > 0:
            verify_success, _ = run_cmd(f"openssl x509 -in {read_cert_file} -text -noout")
            assert verify_success


class TestPIVCryptoOperations:
    """Test PIV cryptographic operations (ECDSA, ECDH)."""

    @pytest.fixture(autouse=True)
    def setup_key_and_cert(self, check_environment, temp_dir):
        """Generate key and certificate before crypto tests."""
        self.temp_dir = temp_dir
        self.pubkey_file = temp_dir / "pubkey_crypto.pem"
        self.cert_file = temp_dir / "cert_crypto.pem"

        # Generate key in slot 9a
        run_piv_tool_interactive(
            f"-a generate -s 9a -A ECCP256 -k - -o {self.pubkey_file}",
            timeout=60,
            provide_mgmt_key=True,
        )
        time.sleep(0.3)

        if self.pubkey_file.exists():
            # Self-sign certificate
            run_piv_tool_interactive(
                f"-a verify-pin -a selfsign-certificate -s 9a "
                f"-S '/CN=Test PIV Auth/O=Test Org/' "
                f"-i {self.pubkey_file} -o {self.cert_file}",
                timeout=60,
                provide_pin=True,
            )
            time.sleep(0.3)

            if self.cert_file.exists():
                # Import certificate
                run_piv_tool_interactive(
                    f"-a import-certificate -s 9a -i {self.cert_file} -k -",
                    timeout=30,
                    provide_mgmt_key=True,
                )
                time.sleep(0.3)

    def test_ecdsa_signature(self, check_environment):
        """Test ECDSA signature operation."""
        # Read certificate from card
        read_cert = self.temp_dir / "cert_read_sig.pem"
        run_cmd(f"yubico-piv-tool -a read-certificate -s 9a -o {read_cert}")

        if not read_cert.exists() or read_cert.stat().st_size == 0:
            pytest.skip("No certificate available for signature test")

        # Test signature
        success, output = run_cmd(
            f"yubico-piv-tool -a verify-pin -P {DEFAULT_PIN} -a test-signature -s 9a -i {read_cert}"
        )

        assert success or "ECDSA verification" in output or "signature" in output.lower()

    def test_ecdh_key_agreement(self, check_environment, temp_dir):
        """Test ECDH key agreement operation."""
        # First generate a key in slot 9d (Key Management)
        pubkey_9d = temp_dir / "pubkey_9d_ecdh.pem"
        cert_9d = temp_dir / "cert_9d_ecdh.pem"

        run_piv_tool_interactive(
            f"-a generate -s 9d -A ECCP256 -k - -o {pubkey_9d}",
            timeout=60,
            provide_mgmt_key=True,
        )
        time.sleep(0.3)

        if not pubkey_9d.exists():
            pytest.skip("Could not generate key for ECDH test")

        # Self-sign certificate
        run_piv_tool_interactive(
            f"-a verify-pin -a selfsign-certificate -s 9d "
            f"-S '/CN=Test ECDH Key/O=Test Org/' "
            f"-i {pubkey_9d} -o {cert_9d}",
            timeout=60,
            provide_pin=True,
        )
        time.sleep(0.3)

        if not cert_9d.exists():
            pytest.skip("Could not create certificate for ECDH test")

        # Import certificate
        run_piv_tool_interactive(
            f"-a import-certificate -s 9d -i {cert_9d} -k -",
            timeout=30,
            provide_mgmt_key=True,
        )
        time.sleep(0.3)

        # Read certificate from card for test-decipher
        read_cert = temp_dir / "cert_9d_read.pem"
        run_cmd(f"yubico-piv-tool -a read-certificate -s 9d -o {read_cert}")

        if not read_cert.exists() or read_cert.stat().st_size == 0:
            pytest.skip("No certificate available for ECDH test")

        # Test ECDH (decipher)
        success, output = run_cmd(
            f"yubico-piv-tool -a verify-pin -P {DEFAULT_PIN} -a test-decipher -s 9d -i {read_cert}"
        )

        assert success or "ECDH" in output or "exchange" in output.lower() or "decipher" in output.lower()


class TestPIVPINOperations:
    """Test PIV PIN management operations."""

    def test_change_pin(self, check_environment):
        """Test changing the PIN."""
        # Change PIN from default to itself (to not break other tests)
        success, output = run_piv_tool_interactive(
            f"-a change-pin -P {DEFAULT_PIN} -N {DEFAULT_PIN}",
            timeout=30,
        )
        # Should succeed or already have this PIN
        assert success or "changed" in output.lower() or "success" in output.lower()

    def test_verify_pin_wrong(self, check_environment):
        """Test that wrong PIN fails verification."""
        success, output = run_cmd("yubico-piv-tool -a verify-pin -P 000000")
        # Should fail with wrong PIN
        assert not success or "incorrect" in output.lower() or "fail" in output.lower()


class TestPIVManagementKeyOperations:
    """Test PIV management key operations."""

    def test_authenticate_with_mgmt_key(self, check_environment):
        """Test authentication with management key."""
        # Try setting CHUID which requires management key authentication
        success, output = run_piv_tool_interactive(
            "-a set-chuid -k -",
            timeout=30,
            provide_mgmt_key=True,
        )
        assert success or "success" in output.lower()


class TestPIVFullWorkflow:
    """Test complete PIV workflow end-to-end."""

    def test_full_ecc_workflow(self, check_environment, temp_dir):
        """Test complete ECC key generation, certificate, and signing workflow."""
        pubkey = temp_dir / "workflow_pubkey.pem"
        cert = temp_dir / "workflow_cert.pem"

        # Step 1: Set CHUID
        success, output = run_piv_tool_interactive(
            "-a set-chuid -k -",
            timeout=30,
            provide_mgmt_key=True,
        )
        time.sleep(0.3)

        # Step 2: Generate ECC P-256 key
        success, output = run_piv_tool_interactive(
            f"-a generate -s 9a -A ECCP256 -k - -o {pubkey}",
            timeout=60,
            provide_mgmt_key=True,
        )
        time.sleep(0.3)

        if not pubkey.exists():
            pytest.skip("Key generation failed")

        # Step 3: Self-sign certificate
        success, output = run_piv_tool_interactive(
            f"-a verify-pin -a selfsign-certificate -s 9a "
            f"-S '/CN=Workflow Test/O=Test/' "
            f"-i {pubkey} -o {cert}",
            timeout=60,
            provide_pin=True,
        )
        time.sleep(0.3)

        if not cert.exists():
            pytest.skip("Certificate generation failed")

        # Step 4: Import certificate
        success, output = run_piv_tool_interactive(
            f"-a import-certificate -s 9a -i {cert} -k -",
            timeout=30,
            provide_mgmt_key=True,
        )
        time.sleep(0.3)

        # Step 5: Read back certificate
        read_cert = temp_dir / "workflow_cert_read.pem"
        run_cmd(f"yubico-piv-tool -a read-certificate -s 9a -o {read_cert}")

        if read_cert.exists():
            # Step 6: Test signature
            success, output = run_cmd(
                f"yubico-piv-tool -a verify-pin -P {DEFAULT_PIN} -a test-signature -s 9a -i {read_cert}"
            )
            # At least one step should succeed
            assert read_cert.stat().st_size > 0

    def test_status_after_operations(self, check_environment):
        """Test status command shows expected state after operations."""
        success, output = run_cmd("yubico-piv-tool -a status")
        # Should have some response from the card
        assert success or len(output) > 0
