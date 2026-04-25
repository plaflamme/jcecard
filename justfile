# Justfile for simpcsc development

# Default recipe
default:
    @just --list

# Build the IFD handler (Rust) with the Nitrokey slot-1 card enabled.
# The `nitrokey` cargo feature is default-on, so this produces a two-slot
# libifd_jcecard.so (slot 0 = jcecard, slot 1 = real Nitrokey Trussed stack).
# Pass NK=0 to disable and build a lean slot-0-only handler.
build-ifd NK="1":
    #!/usr/bin/env bash
    set -euo pipefail
    cd ifd-jcecard
    if [ "{{NK}}" = "0" ]; then
        echo "Building libifd_jcecard.so WITHOUT nitrokey (slot-0 only)…"
        cargo build --release --no-default-features
    else
        echo "Building libifd_jcecard.so WITH nitrokey (slots 0 + 1)…"
        cargo build --release --features nitrokey
    fi
    ls -lh target/release/libifd_jcecard.so

# Package the IFD handler as a tarball
package-ifd: build-ifd
    #!/usr/bin/env bash
    set -e
    STAGING_DIR=$(mktemp -d)
    PKG_DIR="$STAGING_DIR/ifd-jcecard"
    mkdir -p "$PKG_DIR"

    # Copy the built library
    cp ifd-jcecard/target/release/libifd_jcecard.so "$PKG_DIR/"

    # Copy bundle configuration files (flattened structure for easy install)
    cp ifd-jcecard/bundle/ifd-jcecard.bundle/Contents/Info.plist "$PKG_DIR/"
    cp ifd-jcecard/bundle/jcecard.conf "$PKG_DIR/"

    # Copy install and startup scripts
    cp scripts/install-jcecard.sh "$PKG_DIR/"
    cp scripts/start-pcscd-debug.sh "$PKG_DIR/"
    chmod +x "$PKG_DIR/install-jcecard.sh"
    chmod +x "$PKG_DIR/start-pcscd-debug.sh"

    # Create tarball
    tar -C "$STAGING_DIR" -czvf ifd-jcecard.tar.gz ifd-jcecard

    # Print sha256sum
    echo ""
    echo "Package created: ifd-jcecard.tar.gz"
    sha256sum ifd-jcecard.tar.gz

    # Cleanup
    rm -rf "$STAGING_DIR"

    echo ""
    echo "To install on target system:"
    echo "  tar xzf ifd-jcecard.tar.gz"
    echo "  cd ifd-jcecard"
    echo "  sudo ./install-jcecard.sh"

# Install the IFD handler to pcscd drivers directory
install-ifd: build-ifd
    #!/usr/bin/env bash
    set -euo pipefail
    BUNDLE_DIR="/usr/lib/pcsc/drivers/ifd-jcecard.bundle"
    CONF_DIR="/etc/reader.conf.d"
    IFD_DIR="ifd-jcecard"
    SO="$IFD_DIR/target/release/libifd_jcecard.so"

    if [ ! -f "$SO" ]; then
        echo "error: $SO not found — did build-ifd succeed?" >&2
        exit 1
    fi

    # Detect whether this .so was built with the nitrokey feature.
    # The Trussed stack adds ~1.5 MB of compiled code, so a size threshold
    # is a cheap, strip-resistant signal (symbol checks fail under
    # `strip = true` in release).
    SIZE=$(stat -c%s "$SO" 2>/dev/null || stat -f%z "$SO")
    if [ "$SIZE" -gt 2000000 ]; then
        echo "Detected: .so size ${SIZE} B — nitrokey slot-1 present (real Trussed stack embedded)."
    else
        echo "Warning: .so size ${SIZE} B < 2 MB — nitrokey slot-1 likely NOT present."
        echo "         Rebuild with 'just build-ifd' (default) to include it."
    fi

    echo "Installing driver bundle to $BUNDLE_DIR …"
    sudo mkdir -p "$BUNDLE_DIR/Contents/Linux"
    sudo cp "$IFD_DIR/bundle/ifd-jcecard.bundle/Contents/Info.plist" "$BUNDLE_DIR/Contents/"
    sudo cp "$SO" "$BUNDLE_DIR/Contents/Linux/"

    echo "Installing reader configuration to $CONF_DIR/jcecard …"
    sudo mkdir -p "$CONF_DIR"
    sudo cp "$IFD_DIR/bundle/jcecard.conf" "$CONF_DIR/jcecard"

    echo "IFD handler installed. Run 'just restart-pcscd' to pick it up."

# Uninstall the IFD handler from pcscd drivers directory
uninstall-ifd:
    #!/usr/bin/env bash
    set -e
    BUNDLE_DIR="/usr/lib/pcsc/drivers/ifd-jcecard.bundle"
    CONF_DIR="/etc/reader.conf.d"
    
    echo "Uninstalling driver bundle..."
    sudo rm -rf "$BUNDLE_DIR"
    
    echo "Uninstalling reader configuration..."
    sudo rm -f "$CONF_DIR/jcecard"
    
    echo "IFD handler uninstalled successfully"

# Restart pcscd in debug mode and verify both slots are visible.
# Passes JCECARD_STORAGE_DIR so slot 0 (card_state.json) and slot 1
# (littlefs images + OATH store) both land in the invoking user's $HOME
# even though pcscd runs as root.
restart-pcscd:
    #!/usr/bin/env bash
    set -euo pipefail
    sudo pkill -9 pcscd 2>/dev/null || true
    sudo systemctl stop pcscd.socket pcscd.service 2>/dev/null || true
    sleep 1
    echo "Starting pcscd with JCECARD_STORAGE_DIR=$HOME/.jcecard …"
    sudo env JCECARD_STORAGE_DIR="$HOME/.jcecard" \
        /usr/sbin/pcscd --foreground --debug --apdu \
        > /tmp/pcscd_debug.log 2>&1 &
    # Slot 1 mounts two on-disk littlefs volumes on first boot — give it
    # a moment before we poke it for the reader list.
    sleep 3
    echo
    echo "Verifying readers advertised by pcscd:"
    # Prefer the venv python (where pyscard is installed) over system
    # python3.
    PY_BIN="$(pwd)/.venv/bin/python3"
    [ -x "$PY_BIN" ] || PY_BIN="$(command -v python3 || true)"
    if [ -n "$PY_BIN" ]; then
        "$PY_BIN" - <<'PY' || true
    try:
        from smartcard.System import readers
    except Exception as e:
        print(f"  (pyscard not available: {e})")
        print(f"  hint: source .venv/bin/activate && pip install pyscard")
    else:
        rs = readers()
        if not rs:
            print("  NONE — check /tmp/pcscd_debug.log")
        for r in rs:
            print(f"  - {r}")
    PY
    else
        echo "  (python3 not found — inspect /tmp/pcscd_debug.log for slot traffic)"
    fi
    echo
    echo "pcscd logs: /tmp/pcscd_debug.log"

# Restart pcscd (alias for restart-pcscd)
restart-all: restart-pcscd

# Run RSA signing tests
test-rsa-sign:
    source .venv/bin/activate && timeout 300 pytest tests/test_smartcard_crypto.py::TestSmartcardRSAOperations::test_rsa_sign_and_verify tests/test_smartcard_crypto.py::TestSmartcardRSAOperations::test_rsa_sign_multiple_messages -xvs

# Run all RSA tests
test-rsa:
    source .venv/bin/activate && timeout 300 pytest tests/test_smartcard_crypto.py::TestSmartcardRSAOperations -xvs

# Check if pcscd is running
status:
    @echo "pcscd:"
    @pgrep pcscd && echo "  Running" || echo "  Not running"

# CI: Install ifd from kushal's build for speedup
install-prbuilt-ifd:
    #!/usr/bin/env bash
    set -e
    wget https://kushaldas.in/ifd-jcecard.tar.gz
    echo "b9f10211f2c283829f0018d6254279387f131e3003df3084d0f4717f241d0ba5  ifd-jcecard.tar.gz" | sha256sum -c -
    tar xvf ifd-jcecard.tar.gz
    cd ifd-jcecard
    sudo ./install.sh

# Full rebuild: build IFD, install, and restart pcscd
rebuild: install-ifd restart-pcscd
    @echo "Full rebuild complete"

# Check linting with ty & ruff
lint:
    #!/usr/bin/env bash
    set -x
    source .venv/bin/activate
    ty check .
    ruff check .

# Configure gpg-agent for loopback pinentry and restart it
gpg-loopback:
    #!/usr/bin/env bash
    set -e
    mkdir -p ~/.gnupg
    chmod 700 ~/.gnupg
    grep -q "allow-loopback-pinentry" ~/.gnupg/gpg-agent.conf 2>/dev/null || echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
    gpgconf --kill gpg-agent
    gpg-connect-agent /bye
    echo "gpg-agent configured for loopback pinentry and restarted"

# CI: Install system dependencies
ci-install-deps:
    #!/usr/bin/env bash
    set -e
    sudo apt-get update
    sudo apt-get install -y \
      pcscd \
      libpcsclite-dev \
      libpcsclite1 \
      pcsc-tools \
      gnupg \
      gnupg-agent \
      scdaemon \
      libclang-dev \
      nettle-dev \
      pkg-config \
      build-essential

# CI: Install yubico-piv-tool from kushal's build
ci-install-yubico:
    #!/usr/bin/env bash
    set -e
    wget https://kushaldas.in/yubico.tar.gz
    echo "222b9deb97dcd2ad03f216ac42caea91bd875d6f3e838d3f4a9ab0d01c433c4c  yubico.tar.gz" | sha256sum -c -
    tar xvf yubico.tar.gz
    sudo apt install ./yubico/*.deb

# CI: Create Python virtualenv and install dependencies
ci-setup-venv:
    #!/usr/bin/env bash
    set -e
    python -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    python -m pip install pexpect pyscard

# Run Rust unit tests
test-rust:
    cd ifd-jcecard && cargo test

# Run Rust unit tests WITHOUT the nitrokey slot-1 feature (pure jcecard path)
test-rust-no-nk:
    cd ifd-jcecard && cargo test --no-default-features

# Smoke-check the slot-1 Nitrokey card directly against pynitrokey (local checkout)
test-nitrokey:
    #!/usr/bin/env bash
    set -e
    if [ ! -d pynitrokey ]; then
        echo "pynitrokey checkout missing at ./pynitrokey" >&2
        exit 1
    fi
    source .venv/bin/activate 2>/dev/null || true
    cd pynitrokey && python -m pynitrokey.cli nk3 piv info || true

# Wipe slot-1 state (Trussed littlefs images + OATH store) for a clean
# Nitrokey-side reset. Slot 0 (jcecard OpenPGP/PIV) is untouched.
# pcscd runs as root, so the .bin images are root-owned — use sudo.
reset-nitrokey:
    sudo rm -rf "$HOME/.jcecard/slot-1"
    @echo "Slot-1 state wiped: $HOME/.jcecard/slot-1"

# Show which PC/SC readers pcscd currently exposes. Expect two entries
# ending "00 00" (jcecard slot 0) and "00 01" (Nitrokey slot 1) when
# pcscd is running with our handler installed.
show-readers:
    #!/usr/bin/env bash
    PY_BIN="$(pwd)/.venv/bin/python3"
    [ -x "$PY_BIN" ] || PY_BIN="$(command -v python3 || true)"
    if [ -n "$PY_BIN" ]; then
        "$PY_BIN" - <<'PY'
    try:
        from smartcard.System import readers
    except Exception as e:
        print(f"pyscard not available: {e}")
    else:
        rs = readers()
        if not rs:
            print("No readers found — is pcscd running? (just restart-pcscd)")
        for r in rs:
            print(f" - {r}")
    PY
    else
        echo "python3 not found; run: pcsc_scan -n"
    fi

# Re-sync the vendored Nitrokey 3 firmware component crates from an upstream
# checkout. Defaults to ~/code/openpgp/nitrokey-3-firmware; override with SRC=…
#
# Example: just sync-nitrokey-vendor SRC=/tmp/nitrokey-3-firmware
sync-nitrokey-vendor SRC="~/code/openpgp/nitrokey-3-firmware":
    #!/usr/bin/env bash
    set -euo pipefail
    SRC="{{SRC}}"
    SRC="${SRC/#\~/$HOME}"
    DEST="ifd-jcecard/vendor/nitrokey-3-firmware"

    if [ ! -d "$SRC/components" ]; then
        echo "error: no components/ at $SRC" >&2
        exit 1
    fi

    echo "Syncing nitrokey-3-firmware components"
    echo "  from: $SRC"
    echo "  to:   $DEST"

    mkdir -p "$DEST/components"
    for c in apps utils ndef-app memory-regions provisioner-app; do
        if [ -d "$SRC/components/$c" ]; then
            rsync -a --delete --exclude=target --exclude='*.rlib' \
                "$SRC/components/$c/" "$DEST/components/$c/"
            echo "  - $c"
        else
            echo "  ! skipped (missing in source): $c"
        fi
    done

    # Licenses from upstream root.
    for f in LICENSE-APACHE LICENSE-MIT; do
        if [ -f "$SRC/$f" ]; then
            cp "$SRC/$f" "$DEST/$f"
        fi
    done

    # Provenance stamps.
    (cd "$SRC" && git rev-parse HEAD 2>/dev/null) > "$DEST/UPSTREAM_COMMIT" \
        || echo "unknown" > "$DEST/UPSTREAM_COMMIT"
    WS_VER=$(awk -F'"' '/^version = "/ {print $2; exit}' "$SRC/Cargo.toml" || true)
    if [ -n "$WS_VER" ]; then
        echo "v$WS_VER" > "$DEST/UPSTREAM_TAG"
    fi

    # Keep the local minimal workspace Cargo.toml in sync with upstream's
    # [workspace.package] version so the vendored sub-crates' `workspace = true`
    # inheritance still resolves.
    if [ -n "$WS_VER" ]; then
        sed -i -E "s/^version = \"[^\"]+\"/version = \"$WS_VER\"/" \
            "$DEST/Cargo.toml"
        echo "  - workspace Cargo.toml version -> $WS_VER"
    fi

    echo
    echo "Synced: $(cat "$DEST/UPSTREAM_TAG" 2>/dev/null || echo '(no tag)') @ $(cat "$DEST/UPSTREAM_COMMIT")"
    echo "Next step: cargo build --manifest-path ifd-jcecard/Cargo.toml --features nitrokey"

# CI: Build Rust IFD handler
ci-build-ifd: build-ifd

# CI: Configure gpg-agent for loopback pinentry
ci-gpg-loopback:
    #!/usr/bin/env bash
    set -e
    mkdir -p ~/.gnupg
    chmod 700 ~/.gnupg
    echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
    echo "disable-ccid" >> ~/.gnupg/scdaemon.conf
    gpgconf --kill all || true


# CI: Start pcscd (virtual card is embedded in IFD handler)
ci-start-services:
    #!/usr/bin/env bash
    set -e
    source .venv/bin/activate
    # Stop any existing pcscd first (ubuntu-latest has it running by default)
    sudo systemctl stop pcscd.socket pcscd.service 2>/dev/null || true
    sudo pkill -9 pcscd 2>/dev/null || true
    sleep 1
    # Start pcscd in debug mode with polkit disabled (required for CI)
    # Ubuntu's pcscd 2.0+ uses polkit for authorization which blocks non-root users
    # Set JCECARD_STORAGE_DIR to user's home for state persistence
    sudo JCECARD_STORAGE_DIR="$HOME/.jcecard" /usr/sbin/pcscd --foreground --debug --apdu --disable-polkit > /tmp/pcscd_debug.log 2>&1 &
    # Slot 1 mounts two on-disk littlefs volumes on first boot — give it a
    # moment before we query the reader list.
    sleep 7
    # Verify pcscd is running
    pgrep pcscd && echo "pcscd is running"
    # Verify BOTH readers (slot 0 + slot 1) are advertised by pcscd. With
    # default cargo features (nitrokey on), the handler exposes
    # TAG_IFD_SLOTS_NUMBER=2; pcscd should therefore surface two readers
    # suffixed " 00 00" and " 00 01".
    python - <<'PY'
    from smartcard.System import readers
    rs = [str(r) for r in readers()]
    print(f"Readers: {rs}")
    assert len(rs) >= 2, f"Expected 2 readers (slot 0 + slot 1), got {len(rs)}"
    assert any(name.endswith('00 00') for name in rs), "Slot 0 reader (suffix '00 00') missing"
    assert any(name.endswith('00 01') for name in rs), "Slot 1 reader (suffix '00 01') missing — nitrokey feature not built in?"
    print("Both slots present.")
    PY

# CI: Verify both readers are visible (used outside ci-start-services for diagnostics).
verify-readers:
    #!/usr/bin/env bash
    PY_BIN="$(pwd)/.venv/bin/python3"
    [ -x "$PY_BIN" ] || PY_BIN="$(command -v python3 || true)"
    "$PY_BIN" - <<'PY'
    from smartcard.System import readers
    rs = [str(r) for r in readers()]
    for r in rs:
        print(f"  - {r}")
    assert len(rs) >= 2, f"Expected 2 readers, got {len(rs)}"
    assert any(n.endswith('00 00') for n in rs)
    assert any(n.endswith('00 01') for n in rs)
    print("OK")
    PY

# CI: Run tests (Rust + Python integration). The 900s timeout covers
# first-boot littlefs format on slot 1 + RSA-4096 keygen.
ci-test:
    #!/usr/bin/env bash
    set -e
    source .venv/bin/activate
    timeout 900 pytest -vvv

# CI: Cargo clippy / test in slot-0-only mode (no nitrokey feature).
# Catches accidental nitrokey-required code outside the cargo gate.
ci-test-no-nk:
    #!/usr/bin/env bash
    set -e
    cd ifd-jcecard
    cargo clippy --no-default-features -- -D warnings
    cargo test --no-default-features

