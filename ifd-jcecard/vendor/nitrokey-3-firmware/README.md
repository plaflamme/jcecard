# Vendored Nitrokey 3 firmware component crates

This directory contains a snapshot of the `components/` sub-crates from
[nitrokey-3-firmware](https://github.com/Nitrokey/nitrokey-3-firmware) that
the slot-1 `NitrokeyCard` depends on. Vendoring keeps the repo self-contained
so builds do not require a side-by-side checkout of the firmware.

## What's in here

- `components/apps/`            — applet orchestrator (`apps::Apps`, `apps::Runner`)
- `components/utils/`           — small helpers used by `apps`
- `components/ndef-app/`        — NDEF applet (enabled by the `nk3` feature)
- `components/memory-regions/`  — memory-region descriptors (used via `[patch.crates-io]`)
- `components/provisioner-app/` — optional provisioner applet

`UPSTREAM_COMMIT` and `UPSTREAM_TAG` record the snapshot's provenance.

## How to refresh

Run `just sync-nitrokey-vendor` from the repo root. By default it syncs from
`~/code/openpgp/nitrokey-3-firmware`; override with:

```sh
just sync-nitrokey-vendor SRC=/path/to/nitrokey-3-firmware
```

The recipe:

1. `rsync`s the five component crate trees (deleting removed files).
2. Drops any `target/` directories.
3. Captures the upstream HEAD commit in `UPSTREAM_COMMIT`.
4. Writes the workspace version into `UPSTREAM_TAG`.
5. Copies `LICENSE-APACHE` and `LICENSE-MIT` from the upstream root.

After a sync, run `cargo build --features nitrokey` to confirm everything
still links and `cargo test --features nitrokey` to check for behaviour
regressions.

## Upstream licensing

Upstream is dual Apache-2.0 / MIT. See `LICENSE-APACHE` and `LICENSE-MIT`.
The combined `ifd-jcecard` binary is LGPL-3.0-or-later (inherited from
`opcard-rs`), which is compatible with both of these licenses.
