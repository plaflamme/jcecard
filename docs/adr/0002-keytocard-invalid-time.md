# ADR-0002: `gpg-agent KEYTOCARD` rejects every upload with "Invalid time" — slot-1 key-import test removed

Date: 2026-04-25
Status: Accepted (workaround) / Open (root cause)

## Context

ADR-0001 left an open follow-up: cover opcard-rs's IMPORT KEY path on
slot 1 (the upstream PUT DATA PRIVATE KEY TEMPLATE flow, distinct from
on-card key generation). The cleanest way to drive that from a test
is `gpg --edit-key <fpr> → keytocard`, which makes gpg-agent send a
`KEYTOCARD` Assuan command to scdaemon that ultimately becomes the
right APDUs on the wire.

We tried two test variants:

1. `tests/test_nitrokey_rsa4096.py` — generate an RSA-4096 key
   off-card via `gpg --quick-gen-key` (timestamp = now = 2026), then
   `keytocard` it onto slot 1.
2. `tests/test_nitrokey_upload.py` — import the existing committed
   key `tests/files/primary_with_sign.asc` (Ed25519 + X25519, created
   2022-08-29 — pre-Y2026), then `keytocard` it onto slot 1.

**Both variants failed identically** with:

```
[GNUPG:] SC_OP_FAILURE
gpg: KEYTOCARD failed: Invalid time
[GNUPG:] ERROR card_key_generate 100663383
```

This rules out a timestamp-year-specific bug.

## What we observed

`gpg-agent --debug-all` log around the failure (2022-dated key):

```
chan_12 <- KEYTOCARD AD33C4DCB531750DF7891DD2887309DF27BD554A
                     D276000124010304000F4E4B00010000
                     OPENPGP.1
                     20220829T160931
chan_12 -> S INQUIRE_MAXLEN 255
chan_12 -> [Confidential data not shown]   ← passphrase prompt
chan_12 <- [Confidential data not shown]   ← user PIN entered
chan_12 <- [Confidential data not shown]
DBG: ecc_testkey info: Edwards/Ed25519+EdDSA
DBG: ecc_testkey ... q: [264 bit] 4024…f769d0
DBG: ecc_testkey ... d: [256 bit] 1a71…7fc8
DBG: ecc_testkey    => Success                ← key decrypts and verifies
S2K calibration: 200324096 -> 284ms
DBG: agent_put_cache 'AD33C4DCB531750DF7891DD2887309DF27BD554A'.0 (mode 0) requested ttl=0
command 'KEYTOCARD' failed: Invalid time     ← rejection happens AFTER
chan_12 -> ERR 67109025 Invalid time <GPG Agent>
```

## What we ruled out

- **Y2026 / Y2038 timestamp wraparound.** Same failure with a 2022
  timestamp and a 2026 timestamp; the rejection is not value-dependent.
- **`isotime2epoch` parsing bug.** The standalone reimplementation of
  `isotime_p` + `isotime_make_tm` + `timegm` returns `1661789371`
  (correct) for `"20220829T160931"`. So the upstream string parser is
  fine on this machine.
- **Ubuntu downstream patches in `cmd_keytocard`.** Pulled
  `gnupg2_2.4.4-2ubuntu17.4.debian.tar.xz` from Launchpad and grepped
  `debian/patches/`. Only patch touching this area is
  `from-master/gpg-default-to-3072-bit-keys.patch`, which only edits
  help text. No backports change `agent/command.c:cmd_keytocard` or
  `common/gettime.c:isotime2epoch`.
- **Stale gpg-agent / scdaemon / dirmngr / keyboxd processes.** Killed
  all four under `$USER` and re-ran from a fresh GNUPGHOME. Same
  rejection.
- **Reader pinning / multi-reader scdaemon ping-pong.** Confirmed in
  the log that the single scdaemon connection never crosses to slot 0
  during these failures. The error is purely on the agent side, before
  any APDU is sent to scdaemon.
- **Pinentry loopback path.** The `INQUIRE` shows the passphrase
  arriving and the secret key successfully decrypting via
  `ecc_testkey ... => Success`. The agent has the unprotected key in
  hand when it then emits "Invalid time".

## What we suspect (not yet pinned)

The agent log shows `agent_put_cache <hexgrip>` happening between
"key decrypts" and "Invalid time". That cache call is the
`CACHE_MODE_NONCE` path inside `agent_key_from_file` for the
just-decrypted key material. The `&timestamp` output parameter is
populated from the on-disk key's `Created:` header.

The only `GPG_ERR_INV_TIME` emitter in `agent/command.c:cmd_keytocard`
is line 3329, gated on `timestamp == (time_t)(-1)`. Either:

1. `agent_key_from_file` is silently overwriting `timestamp` to `-1`
   on a code path we haven't traced yet (e.g. in the `unprotect →
   reprotect → store-back-to-cache` flow that S2K-calibrates here),
   even though the on-disk file has a valid `Created:` line. Then
   line 3296 (`timestamp = isotime2epoch (argv[3])`) is **not**
   reaching `timestamp` because we're hitting an earlier `goto leave`
   path with a pre-baked `INV_TIME`.
2. There is an early-return path in `cmd_keytocard` that we missed,
   gated on a check we haven't identified.

Both require either an instrumented build of gpg-agent or a careful
top-to-bottom re-read of `agent_key_from_file` + `cmd_keytocard`. We
chose to defer.

## Decision

Remove `tests/test_nitrokey_upload.py` and the helper functions that
backed it (`GPGCardHelper.import_armored_key`,
`GPGCardHelper.keytocard_primary_and_subkey`). Slot-1 coverage in the
PR remains the on-card-generate path:

- `tests/test_nitrokey_ecc.py::TestNitrokeyP384` (3 tests) —
  exercises `GENERATE ASYMMETRIC KEY PAIR` for P-384 and validates the
  full sign/verify/encrypt/decrypt cycle through opcard-rs +
  `trussed/p384`.

The IMPORT KEY codepath (PUT DATA tag B6/B8/A4 with the private-key
template) is therefore **not exercised in CI**.

## Reproducer kept on disk for future debugging

The original tests are removed from the working tree. The pieces
needed to repro live in:

- `tests/files/primary_with_sign.asc` (Ed25519/X25519, passphrase
  `redhat`, created 2022-08-29) — already used by
  `tests/test_smartcard_primary.py` for the slot-0 import path, so
  it's not deleted.
- `git log` recovery: see commits introducing
  `tests/test_nitrokey_rsa4096.py` and `tests/test_nitrokey_upload.py`
  (both reverted in the same commit that adds this ADR).

## Consequences

- **Test coverage gap.** No automated coverage of opcard-rs's IMPORT
  KEY APDU handling on slot 1. A regression there would be invisible
  to our test suite.
- **Slot 0 (jcecard) import is still covered** by
  `tests/test_smartcard_primary.py::test_upload_primary_key_and_sign`
  via `johnnycanencrypt`'s `upload_primary_to_smartcard` — which
  sends raw APDUs and bypasses gpg-agent entirely. That confirms the
  import path is fine *for the hand-rolled jcecard*; it tells us
  nothing about the upstream opcard-rs implementation on slot 1.
- **The bug appears to be in the user's local `gpg-agent 2.4.4` build,
  not in our IFD handler / Trussed stack.** A real Nitrokey 3 plugged
  into the same machine would presumably hit the same agent rejection
  before any APDU reaches the device.

## Follow-up paths (pick one when this becomes load-bearing)

1. **Build gpg-agent from source with logging.** Add a printf right
   before line 3329 of `agent/command.c` showing the value of
   `timestamp`, the value of `argv[3]` if any, and `argc`. Run the
   test once. The log will tell us which branch the function takes.
   Estimated effort: 1–2 hours including build of the gnupg tree.

2. **Bypass gpg entirely with raw PC/SC APDUs.** Use `pyscard` to
   send `PUT DATA 4D` (extended header list with Ed25519 private-key
   template) directly to slot 1, then verify with a follow-up
   `00 47 81 00 02 B6 00 00` (read public key) and a PSO
   COMPUTE_SIGNATURE. Bypasses gpg-agent completely and is the
   cleanest integration test of opcard-rs's import path. Estimated
   effort: half a day, mostly to assemble the TLV correctly.

3. **Test with a different gpg version.** Pull a self-built gnupg
   master into a Docker container and re-run the test. If it works
   there, file an Ubuntu / upstream bug. Estimated effort: 2 hours.

4. **Use a real Nitrokey 3.** If the same gpg-agent rejects KEYTOCARD
   against real hardware, the bug is purely client-side and our
   virtual card is innocent. Useful confirmation step before filing
   anything upstream.

## Cross-references

- ADR-0001 §1.13 mentioned this as a follow-up but framed it as
  Y2026-specific. ADR-0001 §1.13's framing is now superseded by this
  ADR — the failure is timestamp-value-independent.
- The vendored `opcard-rs` and `apps` patches (ADR-0001 §1.5 and §1.6)
  are unaffected; this is purely a gpg-agent client-side issue.
