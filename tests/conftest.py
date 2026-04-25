"""
Pytest configuration and fixtures for OpenPGP card tests.
"""

import pytest
import time
import hashlib
import os
import subprocess
from pathlib import Path


# Import modules to test
from jcecard.card_data import CardState, PINData
from jcecard.pin_manager import PINManager


def get_card_state_path() -> Path:
    """Get the path to the slot-0 card state file."""
    return Path(os.path.expanduser("~/.jcecard")) / "slot-0" / "card_state.json"


def kill_gpg_agents():
    """Kill gpg-agent and scdaemon to release card."""
    try:
        # Use gpgconf to properly kill the agents
        subprocess.run(["gpgconf", "--kill", "all"], capture_output=True, timeout=5)
    except Exception:
        pass
    # Also try direct kill as fallback
    try:
        subprocess.run(["pkill", "-9", "scdaemon"], capture_output=True, timeout=5)
    except Exception:
        pass
    try:
        subprocess.run(["pkill", "-9", "gpg-agent"], capture_output=True, timeout=5)
    except Exception:
        pass
    # Give time for processes to die and release card
    time.sleep(0.5)


@pytest.fixture
def jcecard_process():
    """
    Fixture that ensures the jcecard TCP server is running.
    
    With the new TCP-based architecture, the jcecard TCP server must be
    started separately before running tests. This fixture verifies
    connectivity by checking if pcscd can see the card.
    
    To start the TCP server manually:
        python -m jcecard.tcp_server --debug
    
    Then start pcscd in debug mode:
        sudo /usr/sbin/pcscd --foreground --debug --apdu
    """
    # Kill any existing gpg-agent/scdaemon to release card before test
    kill_gpg_agents()
    
    # Check if we can connect to the card via pcscd
    try:
        from smartcard.System import readers
        reader_list = readers()
        
        if not reader_list:
            pytest.skip(
                "No readers found. Ensure jcecard TCP server and pcscd are running.\n"
                "Start TCP server: python -m jcecard.tcp_server --debug\n"
                "Start pcscd: sudo /usr/sbin/pcscd --foreground --debug --apdu"
            )
        
        # Check if jcecard virtual reader is present
        jcecard_reader = None
        for reader in reader_list:
            if "jcecard" in str(reader).lower():
                jcecard_reader = reader
                break
        
        if not jcecard_reader:
            pytest.skip(
                "jcecard Virtual OpenPGP Card reader not found.\n"
                "Ensure IFD handler is installed and pcscd is running."
            )
        
        # Try to connect to verify the card is responsive
        assert jcecard_reader is not None, "jcecard reader not found"
        connection = jcecard_reader.createConnection()
        connection.connect()
        atr = connection.getATR()
        connection.disconnect()
        
        if not atr:
            pytest.skip("Card not responding - check TCP server logs")
        
    except Exception as e:
        pytest.skip(f"Failed to connect to card: {e}")
    
    # Give any previous operations time to settle
    time.sleep(0.1)
    
    # Yield None since we don't need to manage a process anymore
    yield None
    
    # After test: kill gpg-agent/scdaemon to release card for next test
    kill_gpg_agents()


@pytest.fixture
def default_pin_data():
    """Create PINData with default PINs (123456 / 12345678)."""
    pin_data = PINData()
    pin_data.pw1_hash = hashlib.sha256(b"123456").digest()
    pin_data.pw1_length = 6
    pin_data.pw3_hash = hashlib.sha256(b"12345678").digest()
    pin_data.pw3_length = 8
    return pin_data


@pytest.fixture
def card_state(default_pin_data):
    """Create a CardState with default PINs configured."""
    state = CardState()
    state.pin_data = default_pin_data
    return state


@pytest.fixture
def pin_manager(card_state):
    """Create a PINManager with default card state."""
    return PINManager(card_state)


@pytest.fixture
def sample_tlv_data():
    """Sample TLV data for testing."""
    return {
        # Simple TLV: tag=0x5F50 (URL), length=10, value="example.com"
        "simple": bytes.fromhex("5F500A6578616D706C652E636F6D"),  # URL DO
        # Constructed TLV: Application Related Data (6E)
        "constructed": bytes.fromhex("6E0A5F500762696E617279"),
        # Nested TLV structure
        "nested": bytes.fromhex(
            "6E"  # Application Related Data
            "12"  # Length = 18
            "4F07"  # AID tag, length 7
            "D276000124010304"  # AID value
            "5F500B"  # URL tag, length 11
            "6578616D706C652E636F6D"  # URL value
        ),
    }


@pytest.fixture
def sample_apdu_commands():
    """Sample APDU command bytes for testing."""
    return {
        # SELECT by AID
        "select": bytes.fromhex("00A4040006D27600012401"),
        # VERIFY PW1 (mode 81) with PIN "123456"
        "verify_pw1": bytes.fromhex("00200081063132333435360000"),
        # GET DATA (Application Related Data)
        "get_data": bytes.fromhex("00CA006E00"),
        # Case 1: No data in, no data expected
        "case1": bytes.fromhex("00C00000"),
        # Case 2: No data in, Le bytes expected
        "case2": bytes.fromhex("00CA006E00"),
        # Case 3: Data in, no response data expected
        "case3": bytes.fromhex("00DA005E04DEADBEEF"),
        # Case 4: Data in, response expected
        "case4": bytes.fromhex("002A9E9A0B48656C6C6F576F726C6400"),
    }


@pytest.fixture
def sample_apdu_responses():
    """Sample APDU response bytes for testing."""
    return {
        # Success
        "success": bytes.fromhex("9000"),
        # Success with data
        "success_with_data": bytes.fromhex("DEADBEEF9000"),
        # Wrong PIN (2 tries remaining)
        "wrong_pin_2": bytes.fromhex("63C2"),
        # PIN blocked
        "pin_blocked": bytes.fromhex("6983"),
        # File not found
        "not_found": bytes.fromhex("6A82"),
        # Wrong length
        "wrong_length": bytes.fromhex("6700"),
        # More data available
        "more_data": bytes.fromhex("6110"),
    }
