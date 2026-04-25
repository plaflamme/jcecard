# ADR-0001: Add a Nitrokey-backed virtual card on slot 1

Date: 2026-04-25
Status: Accepted

This document records every architectural and engineering decision taken
while adding a second virtual card to `ifd-jcecard`, backed by the real
upstream Nitrokey 3 firmware components. It is broken into numbered
sub-decisions so each can be revised independently.

---

## Context

`ifd-jcecard` started life as a single-slot IFD handler exposing one
hand-rolled OpenPGP/PIV card aimed at testing
[johnnycanencrypt](https://github.com/kushaldas/johnnycanencrypt). To
exercise our code against a second, independent reference
implementation on the same host, we wanted a second virtual card that
behaves like a Nitrokey 3 — same ATR, same OpenPGP/PIV surface, same
algorithms — driven by the actual upstream firmware code, not our own
re-implementation.

The decisions below are the result of that work. They are listed in
the order they were made; later decisions sometimes invalidate or
constrain earlier ones, in which case both are recorded.

---

## ADR-1.1: Embed the real upstream Nitrokey 3 stack in our IFD handler

**Decision.** Slot 1 runs the real upstream `admin-app`, `opcard`,
`piv-authenticator`, `secrets-app`, `ndef-app` crates from
`nitrokey-3-firmware` v1.8.3, dispatched through `apdu-dispatch` on top
of a host-side Trussed service. Slot 0 keeps the existing hand-rolled
jcecard implementation.

**Considered.**

- *(A) Embed upstream applets in-process.* Chosen.
- *(B) Stub the applet surface ourselves.* Discarded — the user
  explicitly asked for the real opcard-rs / piv-authenticator code,
  and a stub would not catch upstream regressions.
- *(C) Bridge to Nitrokey's `runners/usbip` over `vhci-hcd`.* Discarded —
  needs a kernel module and root, the CCID transport in `pc-usbip-runner`
  is documented as flaky, and it doesn't run as part of our pcscd.

**Consequences.**

- pcscd loads a single `libifd_jcecard.so` and exposes two readers
  (suffix `00 00` for slot 0, `00 01` for slot 1). See
  `ifd-jcecard/src/lib.rs` and `TAG_IFD_SLOTS_NUMBER = 2`.
- Pulls in ~50 transitive Trussed crates. Release `.so` grew from 1.3 MB
  to 2.8 MB. Acceptable.
- The slot-1 path is gated behind the `nitrokey` cargo feature
  (default-on); `--no-default-features` produces the slot-0-only build.

---

## ADR-1.2: Vendor the firmware component crates rather than path-dep
## the user's checkout

**Decision.** `components/{apps,utils,ndef-app,memory-regions,provisioner-app}`
from `nitrokey-3-firmware` are vendored under
`ifd-jcecard/vendor/nitrokey-3-firmware/components/`, plus a minimal
workspace `Cargo.toml` that satisfies `workspace = true` inheritance
(`workspace.package.version = "1.8.3"`,
`workspace.dependencies.littlefs2 = "0.7"`). Provenance is recorded in
`UPSTREAM_COMMIT` and `UPSTREAM_TAG`. `just sync-nitrokey-vendor`
re-rsyncs from a configurable upstream checkout.

**Considered.**

- *(A) Vendor.* Chosen — repo is self-contained, builds without a
  side-by-side firmware checkout.
- *(B) Path-dep on `~/code/openpgp/nitrokey-3-firmware`.* Discarded —
  works on developer machines but breaks fresh clones and CI.
- *(C) Crates.io.* Not possible — `apps`, `utils`, `memory-regions` are
  not published.

**Consequences.**

- The vendored tree is ~220 KB, easy to review.
- Updating means running `just sync-nitrokey-vendor` and re-applying our
  local patches (ADR-1.5, ADR-1.6). The sync recipe stamps the new
  commit/tag automatically.
- Diverges trivially from a real NK3 — none of the vendored crates'
  `no_std` boundaries change behaviour on the host.

---

## ADR-1.3: Vendor `opcard-rs` locally as well

**Decision.** `opcard` v1.7.0 is vendored at `ifd-jcecard/vendor/opcard-rs/`
and pinned via `[patch.crates-io]` → `path = "vendor/opcard-rs"`.

**Considered.**

- *(A) Vendor.* Chosen — we need to apply ADR-1.5 (KDF-DO patch) and
  potentially more upstream fixes; vendoring keeps that tractable.
- *(B) Maintain a fork/branch on Nitrokey's GitHub.* More overhead and
  out-of-band; defer until the patch needs to be public.

**Consequences.**

- One additional vendored crate (~similar size to apps).
- All other Trussed deps (`trussed`, `trussed-rsa-alloc`,
  `trussed-staging`, `admin-app`, `piv-authenticator`, `secrets-app`,
  `pc-usbip-runner`) are still git-pinned via `[patch.crates-io]` to the
  exact revisions from nitrokey-3-firmware v1.8.3's workspace. We can
  vendor more if/when we need to patch them too.

---

## ADR-1.4: Enable `trussed/p384` and `trussed/p521` software backends

**Decision.** `ifd-jcecard/Cargo.toml`'s `trussed` dep is declared with
`features = ["p384", "p521"]`, in addition to the features that
`apps/nk3` already enables (`p256`, `ed255`, `x255`, ...).

**Why this is necessary.** Real NK3 hardware delegates P-384/P-521 to
the NXP SE050 secure element. `components/apps`'s `validate_mechanisms`
const check has a special bypass for these curves under the
`trussed-usbip` feature so that the firmware compiles without an SE050
backend, but **at runtime** Trussed has no implementation for those
curves and operations fail. Enabling `trussed/p384`/`p521` brings in the
pure-Rust software impls (the same `p384`/`p521` crates jcecard slot 0
uses), which the dispatcher then routes to.

**Considered.**

- *(A) Enable software backends.* Chosen.
- *(B) Skip P-384/P-521 entirely on slot 1.* Discarded — would limit our
  test surface to P-256/Ed25519/X25519/RSA, which loses parity with
  jcecard's slot-0 OpenPGP P-384 tests.
- *(C) Stub an SE050 backend.* Significantly more work than just enabling
  the existing software backends.

**Consequences.**

- Slot 1 supports the same ECC curves as a real NK3 with SE050.
- Pulls in additional crypto crates already present elsewhere in our tree.

---

## ADR-1.5: Patch opcard-rs's default KDF-DO value

**Decision.** `vendor/opcard-rs/src/state.rs:1513`'s default for
`Self::KdfDo` was changed from `Bytes::from(&hex!("F9 03 81 01 00"))`
(5 bytes, double-tagged) to `Bytes::from(&hex!("81 01 00"))` (3 bytes,
inner only).

**Why.** OpenPGP card v3.4 §4.4.3.9 says GET DATA for DO 0x00F9
(KDF-DO) returns the **inner** TLV content. Upstream prepends an
`F9 03` outer header which is the BER-TLV header that the GET DATA
machinery is supposed to strip. With the original value present,
scdaemon's parsing of the KDF-DO is undefined: although our specific
kdf=0 path isn't hit (`buflen=5 < KDF_DATA_LENGTH_MIN=90`), the
upstream output is still spec-incorrect and worth fixing while we're in
the file.

**Considered.**

- *(A) Patch opcard's default value to spec.* Chosen.
- *(B) Mask off the KDF capability bit in the Extended Capabilities DO
  (ADR-1.6's first attempt).* Discarded — that lies about card
  capabilities and was speculatively wrong (the 0x40-padded VERIFY
  APDUs we were chasing turned out to be gpg's intentional
  factory-reset behaviour, not a KDF-DO interpretation bug — see
  `gnupg/g10/card-util.c:2057`).

**Consequences.**

- Status line `kdf=0` now correctly reports KDF disabled. (It already
  was, thanks to the upstream `kdf algorithm = 0x00` byte; we just
  emit it cleanly.)
- Worth reporting upstream to opcard-rs.

---

## ADR-1.6: Widen `apps` `allowed_imports`/`allowed_generation` to
## include P-384, P-521, RSA-3072, RSA-4096

**Decision.** `vendor/.../components/apps/src/lib.rs:1098` was changed
from
```rust
options.allowed_generation = Alg::P_256 | Alg::RSA_2048
                           | Alg::X_25519 | Alg::ED_25519;
```
to
```rust
let algs = Alg::P_256 | Alg::P_384 | Alg::P_521
         | Alg::RSA_2048 | Alg::RSA_3072 | Alg::RSA_4096
         | Alg::X_25519 | Alg::ED_25519;
options.allowed_imports = algs;
options.allowed_generation = algs;
```

**Why.** Without this, `opcard::gen.rs:44` (`!algo.is_allowed(...)`)
returns `Status::FunctionNotSupported` (`0x6A81`) on
`GENERATE ASYMMETRIC KEY PAIR` for P-384, even though the underlying
Trussed mechanism is implemented (ADR-1.4). The upstream restriction
is a deliberate hardware-availability gate (P-384/P-521 require SE050
on real NK3); on our host build we have software backends, so we
override.

**Consequences.**

- Every algorithm the Trussed dispatcher implements is now generation-
  and import-allowed at the opcard layer. This matches the user's
  expectation that the slot behaves like a fully provisioned NK3.
- Patch is local to the vendored apps crate; survives sync via manual
  re-apply (TODO: have `sync-nitrokey-vendor` warn / patch
  automatically).

---

## ADR-1.7: Trussed runtime model — service thread with mpsc syscall pump

**Decision.** Slot 1 instantiates a `trussed::Service` on a dedicated
background thread, woken by an `std::sync::mpsc` channel. Trussed
clients on the IFD-handler thread (apdu-dispatch + each applet) call
`Syscall::syscall()` which sends on the channel; the service drains and
processes the queued requests, replies via `interchange` channels back
to the client. Our pcscd-side `transmit_apdu` blocks until the
APDU-dispatch interchange has a response or a 2 s deadline elapses.

**Why this shape.** Trussed's design separates clients from the service
via channels, so direct in-line dispatch is impossible without forking
Trussed. The `pc-usbip-runner` reference implementation does the same
shape (one syscall thread + one transport thread); we collapse the
transport into our IFD handler thread.

**Files.**

- `ifd-jcecard/src/nitrokey/card.rs` — `NitrokeyCard`, `Driver`, the
  service-thread spawn, the deadline loop.
- `ifd-jcecard/src/nitrokey/platform.rs` — `DesktopPlatform` (host-side
  `trussed::Platform`), `DiskStorage` / `RamStorage` (`littlefs2`
  drivers), `build_store()` returning `trussed_usbip::Store` with
  `&'static dyn DynFilesystem` references obtained via `Box::leak`.

**Consequences.**

- Each slot-1 instance leaks ~3 boxed Trussed stores per card creation —
  one-shot cost per process lifetime.
- Drop on `NitrokeyCard` signals `stop_tx` and joins the service thread
  cleanly.
- `trussed_usbip::Syscall` doesn't expose a constructor outside its own
  crate, so we ship `DesktopSyscall(mpsc::Sender<()>)` instead.

---

## ADR-1.8: Per-slot persistent storage at `~/.jcecard/slot-{n}/`

**Decision.** Slot 0 keeps `card_state.json` (auto-migrated from the
legacy `~/.jcecard/card_state.json` on first load). Slot 1 stores two
littlefs2 images (`trussed-ifs.bin`, `trussed-efs.bin`) in
`~/.jcecard/slot-1/` plus a RAM volume re-created on every boot. Both
honour the `JCECARD_STORAGE_DIR` environment variable for testability.

**Consequences.**

- `just reset-nitrokey` is `sudo rm -rf ~/.jcecard/slot-1` (pcscd runs
  as root, so the .bin images are root-owned).
- littlefs2 image sizes match NK3 LPC55 (512 B × 128 blocks = 64 KiB per
  volume), so on-disk format is source-compatible with real NK3.
- Storage isolation between slots: mutating slot-0 leaves slot-1
  untouched and vice versa.

---

## ADR-1.9: Repository relicensed BSD-2-Clause → LGPL-3.0-or-later

**Decision.** All licence metadata (`LICENSE`, `ifd-jcecard/LICENSE`,
`Cargo.toml`, `pyproject.toml`) was changed to `LGPL-3.0-or-later`.
Full GPL-3 text in `COPYING` and LGPL-3 text in `COPYING.LESSER` at the
repo root and inside `ifd-jcecard/`.

**Why.** `opcard-rs` is LGPL-3.0. Statically linking it into a
BSD-2-Clause crate would make the combined binary effectively LGPL-3.0
anyway; the cleanest stance is to make the source license match.

**Consequences.**

- Downstream users get a single, unambiguous licence.
- We no longer need a "dual-license / split into two .so files" build
  story.
- `pyproject.toml` PyPI classifier updated to `GNU Lesser General Public
  License v3 or later (LGPLv3+)`.

---

## ADR-1.10: How the IFD handler exposes the two slots to pcscd

**Decision.** Single `reader.conf.d/jcecard` entry, single `LIBPATH`
pointing at `libifd_jcecard.so`. The handler reports
`TAG_IFD_SLOTS_NUMBER = 2`. pcscd then advertises two readers, suffixed
` 00 00` and ` 00 01`. The `Card` trait
(`ifd-jcecard/src/card/card_trait.rs`) abstracts both slots so the
IFDH* entry points are slot-agnostic.

**Consequences.**

- A single `.so` and a single config entry. No need to register two
  bundles.
- `just install-ifd` does a strip-resistant size check (>2 MB) on the
  built `.so` to confirm slot 1 is included, since stripping symbols in
  release builds defeats name-based detection.

---

## ADR-1.11: Test reader pinning — kill the user's `gpg-agent` /
## `scdaemon` per-test

**Decision.** `tests/gpg_card_helper.GPGCardHelper._write_scdaemon_conf`
runs `pkill -u $USER scdaemon; pkill -u $USER gpg-agent` whenever it
sets up the slot-1 fixture, in addition to writing
`scdaemon.conf` with `reader-port "<full reader name>"`,
`reader-port 1`, `disable-ccid`, and `pcsc-shared` into an isolated
`GNUPGHOME`.

**Why.** With two PC/SC readers visible to `pcscd`, `scdaemon` would
ping-pong between them mid-operation (introspection on slot 1, then
extended-APDU GENERATE on slot 0) even with `reader-port` configured.
Killing the user's persistent agents and restarting against the
isolated `GNUPGHOME` is the only reliable way to keep traffic on slot 1.

**Consequences.**

- Tests transiently disrupt the user's gpg-agent (it auto-respawns on
  next gpg invocation; key cache is lost).
- Diagnostic side-benefit: per-test scratch GNUPGHOMEs leave a
  `scdaemon.log` in `/tmp/pytest-of-*/` for forensics.

---

## ADR-1.12: PIN dispatch in pexpect tests by inspecting prompt context

**Decision.** When gpg emits `GET_HIDDEN passphrase.enter`, the helper
inspects `child.before` for human-readable hints (`Admin`, `admin`,
`PW3`, `forced signature PIN`) to decide whether to send
`DEFAULT_ADMIN_PIN` (`12345678`) or `DEFAULT_USER_PIN` (`123456`).

**Why.** The factory-reset → key-attr → generate → keytocard → sign
flow alternates between PW1 and PW3 in non-obvious order:

| Step | PIN |
|------|-----|
| key-attr per slot (sig/enc/auth) | admin (PW3) |
| `SETATTR CHV-STATUS-1` (multi-sign) | admin (PW3) |
| `GENERATE ASYMMETRIC KEY PAIR` | user (PW1) |
| `make_keysig_packet` per subkey | user (PW1) |
| `PUT DATA` of fingerprints / dates | admin (PW3, often cached) |

A naive "send admin then user" loop deadlocks or burns retry counters
(the admin-PIN-too-short error) when gpg interleaves them. Inspecting
the human-readable prompt, even though it's not a documented protocol
artefact, is reliable in practice.

**Considered.**

- *(A) Inspect prompt text.* Chosen.
- *(B) Use gpg's status-fd `INQUIRE` keywords.* Discarded — they don't
  differentiate user/admin in our gpg version.
- *(C) Bypass gpg entirely, send raw APDUs via pyscard.* Reasonable
  follow-up if (A) breaks on a future gpg release; not done now.

**Consequences.**

- Tests are tightly coupled to gpg's English log output. If gpg
  switches to a different prompt locale, this breaks (the matcher uses
  English keywords). Acceptable while pytest runs use the default `C`
  locale.

---

## Side-quests that turned out to be red herrings

These were investigated and discarded; recorded so future debuggers
don't repeat the work:

1. **The `0x40 × 32` VERIFY APDUs.** Initially looked like a scdaemon
   PIN-padding bug. Tracked through `gnupg/scd/app-openpgp.c`'s
   `pin2hash_if_kdf` and `verify_a_chv` paths. Final resolution:
   `gnupg/g10/card-util.c:2055-2064` deliberately sends 32 bytes of
   `0x40` ('@') as wrong PIN to deplete CHV1 and CHV3 retry counters
   during `factory-reset`, before `TERMINATE DF`. Working as designed.

2. **Clearing the KDF capability bit (Extended Capabilities `0x3F` →
   `0x3E`).** Did not change the observed behaviour — see ADR-1.5 for
   why; the actual bug was elsewhere. The change was reverted.

3. **Numeric `reader-port 1` form.** Added belt-and-braces; the string
   form (`reader-port "jcecard Virtual Smart Card 00 01"`) is what
   scdaemon actually matches on. Both lines are kept; no harm.

---

## Verification

`tests/test_nitrokey_ecc.py::TestNitrokeyP384` exercises the full slot-1
NK3 stack end-to-end:

- `test_generate_p384_keys` — `gpg --edit-card` → P-384 attrs → on-card
  GENERATE for sig/enc/auth → KEY_CREATED
- `test_p384_sign_verify` — detached sign + verify
- `test_p384_encrypt_decrypt` — encrypt + on-card decrypt + roundtrip

All three pass against the patched stack. Rust unit tests (108) remain
green. See `docs/adr/0001-nitrokey-slot1.md` (this file) for the
rationale behind every change required to make this work.

---

## ADR-1.13: ~~RSA-4096 test pivots from `keytocard` to on-card generate~~

**Status.** Superseded by [ADR-0002](./0002-keytocard-invalid-time.md).

The original framing of this sub-decision blamed a "Y2026
`isotime2epoch` quirk" and proposed on-card generate as a workaround.
Re-running the same flow with a 2022-dated key showed the same
"Invalid time" rejection — i.e. the failure is timestamp-value
**independent**, and the workaround was masking a deeper issue without
addressing it. ADR-0002 documents what we actually saw, what we ruled
out, and the decision to drop slot-1 `keytocard` coverage entirely
rather than ship two different on-card-generate tests that exercise
the same code path.

---

## Outstanding work

- Report ADR-1.5 (KDF-DO double-tagging) upstream to opcard-rs.
- ADR-0002 follow-up: cover the `keytocard` import path on slot 1.
  Four candidate paths listed there; the cheapest is probably the
  pyscard-level direct-APDU test.
- Have `just sync-nitrokey-vendor` warn (or auto-reapply) when an
  upstream sync would clobber the patches in ADR-1.5 / ADR-1.6.
