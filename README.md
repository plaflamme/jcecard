# jcecard

A virtual OpenPGP and PIV smart card implementation for testing
[johnnycanencrypt](https://github.com/kushaldas/johnnycanencrypt) and related
desktop applications. The virtual card is embedded in a PC/SC IFD handler
that pcscd loads directly - no external server required.


## Available/tested features for OpenPGP

### Key Types Supported
- **RSA**: 2048, 3072, 4096 bits
- **Curve25519**: Ed25519 (signing), X25519 (decryption)
- **NIST curves**: P-256, P-384 (ECDSA signing, ECDH decryption)
- **secp256k1**: ECDSA signing, ECDH decryption

### Operations
- On-card key generation for all supported algorithms
- Key import for RSA and Curve25519
- Digital signatures (RSA, Ed25519, ECDSA)
- Decryption / key agreement (RSA, X25519, ECDH)
- Authentication (SSH)
- PIN verification and management
- Algorithm attribute changes via `gpg --card-edit` → `key-attr`


## Available/tested features for PIV (via yubico-piv-tool 2.7.2)

- Card status and version information
- PIN verification and PIN change
- Management key authentication (TDES mutual auth)
- Set CHUID (Card Holder Unique Identifier) data object
- Set CCC (Card Capability Container) data object
- On-card ECC P-256 key generation for all slots:
  - Slot 9a (PIV Authentication)
  - Slot 9c (Digital Signature)
  - Slot 9d (Key Management)
  - Slot 9e (Card Authentication)
- Self-signed certificate generation
- Certificate import
- Certificate read
- ECDSA signature operations
- ECDH key agreement (key derivation)
- Full ECC workflow (key generation → certificate → signing)

### Default credentials

- PIN: `123456`
- PUK: `12345678`
- Management Key: `010203040506070801020304050607080102030405060708`

## Using jcecard in CI (GitHub Actions)

Below is an example of how to set up the virtual OpenPGP card in GitHub Actions for testing.

### Required System Dependencies

```yaml
- name: Install system dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y \
      pcscd \
      libpcsclite1 \
      pcsc-tools \
      gnupg \
      scdaemon
```

### Install yubico-piv-tool 2.7.2 for PIV related operations/tests

You will need `yubico-piv-tool` version `2.7.2` for testing the PIV operations.
I have built the package for `ubuntu-latest` on Github.

```yaml
- name: Install yubico-piv-tool from kushal's build
  run: |
    wget https://kushaldas.in/yubico.tar.gz
    echo "222b9deb97dcd2ad03f216ac42caea91bd875d6f3e838d3f4a9ab0d01c433c4c  yubico.tar.gz" | sha256sum -c -
    tar xvf yubico.tar.gz
    sudo apt install ./yubico/*.deb
```

### Install the IFD Handler (Pre-built Binary)

The easiest way to install the IFD handler in CI is to use the pre-built binary:

```yaml
- name: Install jcecard IFD handler
  run: |
    wget https://kushaldas.in/ifd-jcecard.tar.gz
    echo "74ffae1782ba974549783066045d900200609242ce3c23f38a01e3fae1c1d065  ifd-jcecard.tar.gz" | sha256sum -c -
    tar xvf ifd-jcecard.tar.gz
    cd ifd-jcecard
    sudo ./install-jcecard.sh
```

### Set Up Python Environment

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.12'

- name: Create Python virtualenv and install dependencies
  run: |
    python -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    python -m pip install pexpect pyscard
```

### Configure gnupg for Loopback Pinentry

This is required if you want to use `gnupg` with the virtual card in CI:

```yaml
- name: Configure gpg-agent for loopback pinentry
  run: |
    mkdir -p ~/.gnupg
    chmod 700 ~/.gnupg
    echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
    echo "disable-ccid" >> ~/.gnupg/scdaemon.conf
    gpgconf --kill all || true
```

### Start pcscd

```yaml
- name: Start pcscd
  run: |
    # Stop any existing pcscd
    sudo systemctl stop pcscd.socket pcscd.service 2>/dev/null || true
    sudo pkill -9 pcscd 2>/dev/null || true
    sleep 1
    # Start pcscd in debug mode (virtual card is embedded in IFD handler)
    sudo JCECARD_STORAGE_DIR="$HOME/.jcecard" /usr/sbin/pcscd --foreground --debug --apdu --disable-polkit > /tmp/pcscd_debug.log 2>&1 &
    sleep 3
    # Verify pcscd is running and card is available
    pgrep pcscd && echo "pcscd is running"
    source .venv/bin/activate
    python -c "from smartcard.System import readers; r = readers(); print(f'Readers: {r}'); assert len(r) > 0"
```

### Run Your Tests

```yaml
- name: Run tests
  run: |
    source .venv/bin/activate
    timeout 600 pytest tests/ -v
```

### Upload Debug Logs on Failure (Optional)

```yaml
- name: Upload logs on failure
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: debug-logs
    path: /tmp/pcscd_debug.log
    retention-days: 5
```

### Default PINs for OpenPGP card

- **User PIN**: `123456`
- **Admin PIN**: `12345678`


