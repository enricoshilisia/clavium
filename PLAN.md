# Clavium — offline-first password vault and authenticator

## Context

The user wants a standalone security product, separate from the Tenrix
migration platform in every sense: its own repository, its own deploys, no
coupling to this server's existing Django app. The gap it targets is real —
affordable, offline-capable credential management for individuals and small
businesses, growing into a genuine enterprise credential platform (shared
vaults, policies, SSO, audit, and eventually AI-assisted security review) —
without the subscription-gated, cloud-dependent model most competitors
force on every tier.

Scope confirmed directly: **enterprise is the first release target**, the
password vault and the authenticator ship **together** as companion
products from day one, and **Windows, macOS and Linux all ship together**
rather than one platform first. That is the ambition this plan builds
toward — sequenced into real milestones, because even an "all three
platforms, both products, enterprise from day one" release still has a true
dependency order underneath it: a security engine has to exist and be
proven before anything can enforce a policy on it, and a desktop app has to
exist before three platforms' worth of packaging does.

**Product name: Clavium** (from *clavis*, Latin for "key"). Checked against
web search for collision — nothing existing found under that name, unlike
several vault-themed alternatives that turned out to already be real
products (the password-manager naming space is extremely saturated with
vault/key/lock variants, which is itself the reason this plan recommends
staying off that literal root for anything else customer-facing, like
sub-product names).

## Brand direction

Blue as the primary color, with gold as the accent — a deliberate break
from the green/dark palette Tenrix itself uses, since Clavium is a fully
separate brand, not a Tenrix sub-product skin. Blue reads as trustworthy
and institutional (the color most security and financial brands converge
on for a reason); gold against it signals the one or two things that
should actually catch the eye — a security finding worth acting on, a
premium/enterprise tier marker — the same "one accent reserved, not spent
everywhere" discipline Tenrix's own design system already uses with its
green/brass pairing, applied to Clavium's own, different pair. Exact
tokens (hex values, dark-mode variants, contrast-checked accessible
pairings) are a design-pass decision at Milestone 1, once there is a real
desktop shell to apply them to — not guessed at here in the abstract.

## Where this lives

A new, independent repository: **`/home/enrico/clavium/`**, with no import
path to or from `/home/enrico/tenrix` at all — separate git history,
separate deploy, separate everything. If Clavium ever needs to appear
*inside* the Tenrix product later (the pasted research's own long-term
vision — "eventually integrate into your wider cybersecurity platform"),
that is a deliberate, later integration decision, not a day-one coupling.

## Architecture

Four components, each independently deployable, none of them trusting the
others with more than they need:

```
┌─────────────────────┐     ┌──────────────────────┐
│  Clavium Vault        │     │  Clavium Authenticator │
│  (desktop app)         │     │  (mobile app)           │
│  Tauri + React + TS   │     │  React Native            │
└──────────┬───────────┘     └──────────┬───────────┘
           │ local                       │ local
┌──────────▼───────────┐     ┌──────────▼───────────┐
│  Security Core          │     │  Device Keystore        │
│  Rust, audited crates   │     │  iOS Keychain /          │
│  (crypto, key handling) │     │  Android Keystore        │
└──────────┬───────────┘     └──────────┬───────────┘
           │ encrypted payloads over TLS, never plaintext
┌──────────▼─────────────────────────────▼───────────┐
│  Clavium Control Plane (Django REST + PostgreSQL)     │
│  accounts · orgs · device registration · encrypted   │
│  backup storage · audit log · policy enforcement      │
└──────────────────────────────────────────────────────┘
```

**The one rule that makes the whole security story true**: the Control
Plane never holds a master password or a decryption key, and never needs
to decrypt a personal vault to do its job (sync, backup, audit). It stores
and moves encrypted blobs. The one place this gets genuinely hard is
*enterprise shared vaults* — see the key hierarchy below, which is the real
engineering problem Route A (building on an existing vault format) would
have mostly solved for free, and Route B (below) means solving properly.

## The one architectural decision this plan makes, not just presents

The pasted research correctly laid out two routes — build on a KeePass-
compatible foundation (faster MVP, less cryptographic code to invent) or
build a custom Rust engine (full control, no licence constraints, more
security engineering owed up front).

**This plan recommends Route B: a custom Rust security core**, for one
concrete reason that matters given the chosen scope: KeePass-compatible
implementations are GPL-licensed, and an enterprise SaaS product with a
proprietary control plane, policy engine and (eventually) AI layer sitting
on top of a GPL-licensed core is a real legal entanglement to carry into
every enterprise sales conversation and every investor's due diligence —
not a hypothetical. Enterprise-first was the user's own chosen scope; a
custom core is the version of this plan that does not need a licensing
disclaimer on the pricing page.

## Security model (the part that cannot be gotten wrong)

- **Key derivation**: Argon2id, unique salt per vault, parameters
  benchmarked against real target hardware (a slow KDF on a five-year-old
  laptop is a support ticket; a fast one on modern hardware is a weaker
  vault) — tuned once, stored per-vault so an existing vault is never
  silently re-keyed by a parameter change.
- **Encryption**: authenticated encryption only (AES-256-GCM or
  ChaCha20-Poly1305, via `RustCrypto`'s audited crates, never a hand-rolled
  cipher mode) — integrity is checked before any decrypted record is ever
  returned to the UI layer.
- **Local-first truth**: the vault file is fully usable offline; sync and
  backup are additive, never required.
- **Enterprise shared-vault key hierarchy** (the genuinely hard part):
  each shared vault has its own symmetric key; that key is wrapped
  (asymmetrically encrypted) once per authorized member, with each
  member's own public key. The server stores only wrapped keys it cannot
  itself unwrap — granting access means wrapping the vault key with a new
  member's public key, never handing out the raw key, and revoking access
  means removing their wrapped copy and rotating the vault key for
  anything added after that point. This is the same shape Bitwarden and
  1Password's own organization vaults use, not a novel scheme invented for
  this plan — a novel cryptographic scheme is the one thing worth
  deliberately not inventing.
- **Master password / account password are two different secrets**,
  never conflated: the account password (if any) authenticates to the
  Control Plane; the master password derives the vault's own encryption
  key and the server never sees it, in any form, ever.

## Build order

Sequenced so every stage is provable before the next depends on it —
matching the same "prove it live, not just in theory" discipline this
session has held to throughout the Tenrix work.

**Milestone 0 — Security core, provable in isolation**
Rust crate: vault file format, Argon2id derivation, authenticated
encryption, record CRUD against an in-memory and then on-disk encrypted
store. No UI yet. Proven by a command-line test harness: create a vault,
lock it, confirm it is unreadable without the master password, unlock it,
confirm every record round-trips exactly. This is the one piece worth
getting an independent security review on before it is trusted with real
customer data — budgeted as a real line item before any paid release, not
an afterthought.

**Milestone 1 — Desktop shell, one platform first, genuinely**
Tauri + React + TypeScript wrapping Milestone 0's core via Tauri's native
command bridge (Rust functions called directly from the UI, no HTTP hop
for local operations). Vault creation, unlock, record list/search,
password generator, auto-lock timer, local encrypted export/import.
**Built and tested on Linux first** — this environment can actually
compile and run a Tauri app on Linux directly, so this is the one stage
genuinely provable inside this session without needing the user's own
machine. Windows and macOS builds come from the same codebase via Tauri's
cross-compilation/CI pipeline immediately after — "three platforms
together" is honoured by one shared codebase targeting all three from the
start, not three separate builds, but *proving* the Windows and macOS
builds actually run needs those real machines, the same "which device for
what" split this session already used for the file-server collector.

**Milestone 2 — Control plane: accounts and encrypted backup**
Django REST Framework + PostgreSQL. Account registration, device
registration, encrypted vault snapshot upload/download, versioning. The
server-side code is genuinely simple at this stage — it moves and stores
opaque encrypted blobs — which is the point: the hard engineering is
Milestone 0, not this.

**Milestone 3 — Enterprise control plane**
Organizations, members, roles, the shared-vault key-wrapping hierarchy
above, append-only audit log (the exact "actor, object, timestamp,
unwritable" shape this session has enforced all through the Tenrix audit
log, reused here as a proven pattern, not copied code — a separate repo,
the same discipline), offboarding, SSO (OIDC first, SAML once a real
enterprise customer asks for it rather than built speculatively).

**Milestone 4 — Clavium Authenticator**
React Native app (shares TypeScript conventions with the desktop app,
reasonable stack consistency given the team's own background). TOTP/HOTP
generation first — standards-compliant, works with Microsoft 365, Google,
GitHub, anything else that accepts a standard authenticator, provable
immediately against a real account. Push-based approval for Clavium's own
sign-ins second: device key registered at enrollment, every approval
signs a server-issued, single-use, short-lived challenge, number-matching
shown on both ends, rate-limited, revocable per device. Passkeys
(WebAuthn/FIDO2) third, once the above is proven.

**Milestone 5 — AI readiness (architecture only, not features, at this
stage)**
Keep the audit/metadata schema shaped so a later "Ask Clavium" assistant
can query structured facts (password age, reuse, MFA coverage, access
review candidates) without ever needing plaintext vault contents — the
same "facts are the only source of truth, the model explains, it does not
decide" chokepoint this session's own Tenrix work already uses for every
AI feature (`apps.reporting.narrator.narrate()`). Nothing in Milestone 5
is AI code; it is making sure Milestones 2–4's schemas do not have to be
redesigned when AI features actually get built.

## What happens after this plan is approved

Nothing is built yet — this is the plan, not the first commit. Once
approved, the next session's first real step is scaffolding the new
repository and Milestone 0: the Rust security core, proven by its own
command-line test harness before a single line of UI exists.

## Verification, per milestone

- Milestone 0: a scripted CLI harness creating, locking, unlocking and
  round-tripping a real vault file; an intentionally wrong master password
  must fail to unlock, not fail softly.
- Milestone 1: the actual Tauri app, built and run in this environment on
  Linux, exercised by hand — create a vault, add a record, lock, reopen,
  confirm the record is intact.
- Milestone 2: a real account created against a real running Postgres
  instance, a real encrypted snapshot uploaded and restored, confirmed
  byte-identical.
- Milestone 3: two organization members, a shared vault granted to one and
  not the other, confirmed directly against the database that the second
  member's row never had the vault key in any unwrapped form.
- Milestone 4: a real TOTP code generated by Clavium Authenticator,
  entered against a real Microsoft 365 or GitHub account, confirmed it
  authenticates.
