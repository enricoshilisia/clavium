# Clavium

An offline-first password vault and authenticator. Independent product,
independent repository — no coupling to any other codebase.

See `PLAN.md` for the full architecture, security model, and build order.
This file is the state of play; the plan does not change, this does.

## Where things actually stand

**Milestone 0 — security core: built, tested, proven.**

`security-core/` is a Rust crate with no UI and no network — its only job
is that a vault cannot be read without its master password, and can
always be read with it.

- Argon2id key derivation (`kdf.rs`), parameters stored per-vault
- AES-256-GCM authenticated encryption (`crypto.rs`), via RustCrypto's
  audited `aes-gcm` crate
- A real vault file format (`vault.rs`) — magic bytes, version, salt, KDF
  parameters, nonce, ciphertext
- Record CRUD (`record.rs`, `vault.rs`) — create, read, update, delete,
  all round-tripping exactly through a full seal/unlock cycle
- A cryptographically secure password/passphrase generator (`generator.rs`)
- 27 unit tests, including deliberately adversarial ones: wrong password,
  tampered ciphertext, tampered authentication tag, truncated file, wrong
  magic bytes — every one refused cleanly, never a panic, never a silent
  wrong answer

`cli/` is the proof harness — a real command-line tool exercising the
security core exactly the way a future desktop shell will, against real
files on disk:

```
cargo build
./target/debug/clavium-cli create my.vault      # interactive, prompts for a master password
./target/debug/clavium-cli add my.vault --title "Email" --generate
./target/debug/clavium-cli list my.vault
./target/debug/clavium-cli generate --length 24  # no vault needed

# the scripted end-to-end proof the plan's own verification section calls for:
./target/debug/clavium-cli demo /tmp/test.vault
```

**Not started yet**: Milestone 1 (the Tauri desktop shell), Milestone 2
(the Django control plane), Milestone 3 (enterprise — orgs, shared
vaults, SSO), Milestone 4 (the Authenticator companion app). Each is
real, separate work — see `PLAN.md`.

## Development environment

Rust installed via `rustup` (stable channel). `cargo build` / `cargo test`
from the repo root runs the whole workspace.
