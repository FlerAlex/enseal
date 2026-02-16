# enseal

[![CI](https://github.com/FlerAlex/enseal/actions/workflows/ci.yml/badge.svg)](https://github.com/FlerAlex/enseal/actions/workflows/ci.yml)
[![Release](https://github.com/FlerAlex/enseal/actions/workflows/release.yml/badge.svg)](https://github.com/FlerAlex/enseal/actions/workflows/release.yml)
[![Crates.io](https://img.shields.io/crates/v/enseal)](https://crates.io/crates/enseal)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Secure, ephemeral secret sharing for developers.

Stop pasting secrets into Slack. `enseal` makes the secure path faster than the insecure one — share `.env` files and secrets through encrypted, single-use channels with one command and zero setup.

```bash
# sender
$ enseal share .env
  Share code:  7-guitarist-revenge
  Secrets:     14 variables (staging)
  Expires:     5 minutes or first receive

# recipient
$ enseal receive 7-guitarist-revenge
ok: 14 secrets written to .env
```

## Installation

### From crates.io

```bash
cargo install enseal
```

### From source

```bash
git clone https://github.com/YOURUSERNAME/enseal.git
cd enseal
cargo build --release
# binary at ./target/release/enseal
```

### Prebuilt binaries

Download from [GitHub Releases](https://github.com/FlerAlex/enseal/releases) for Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), and Windows.

## Quick Start

### Share a `.env` file

```bash
enseal share .env
```

Give the code to your teammate over any channel — Slack, phone, carrier pigeon. The code is useless without the encrypted channel, and it expires after one use or 5 minutes.

### Receive secrets

```bash
enseal receive 7-guitarist-revenge
```

Writes the `.env` file to disk. Done.

### Share a single secret

```bash
# pipe from anywhere
echo "sk_live_abc123" | enseal share --label "Stripe key"

# recipient gets raw string on stdout
enseal receive 4-orbital-hammock
sk_live_abc123

# pipe to clipboard
enseal receive 4-orbital-hammock | pbcopy
```

### Inject secrets into a process (never touch disk)

```bash
# via wormhole code
enseal inject 7-guitarist-revenge -- npm start
ok: 14 secrets injected into process environment

# via identity listen mode (zero codes, zero coordination)
enseal inject --listen --relay wss://relay.internal:4443 -- npm start
ok: waiting for incoming transfer...
```

Secrets exist only in the child process's memory. When it exits, they're gone.

## Features

### Two Sharing Modes

**Anonymous mode** (default) — wormhole-based, zero setup. A human-readable code is all you need. SPAKE2 mutual authentication prevents MITM attacks.

```bash
enseal share .env                         # generates code
enseal receive 7-guitarist-revenge        # uses code
```

**Identity mode** — public-key encryption for known teammates. Encrypt to a name.

```bash
enseal keys init                          # one-time setup
enseal share .env --to sarah              # encrypt to sarah's public key
```

Identity mode supports three transport options:

```bash
# wormhole (default, no --relay): generates a code like anonymous mode
enseal share .env --to sarah

# relay push (with --relay): zero codes, pushes directly to recipient's channel
enseal share .env --to sarah --relay wss://relay.internal:4443

# file drop (with --output): no network, produces encrypted file
enseal share .env --to sarah --output ./drop/
# produces ./drop/sarah@company.com.env.age
```

### Flexible Input

enseal accepts secrets from multiple sources:

```bash
# .env file (default)
enseal share .env
enseal share staging.env

# environment profile
enseal share --env staging               # resolves to .env.staging

# pipe from stdin
echo "sk_live_abc123" | enseal share
cat secrets.env | enseal share
pass show stripe/key | enseal share --to sarah

# inline (careful — visible in shell history)
enseal share --secret "API_KEY=sk_live_abc123"

# wrap raw string as KEY=VALUE
echo "sk_live_abc123" | enseal share --as STRIPE_KEY
```

### Variable Interpolation

`${VAR}` references are resolved before sending so recipients get fully expanded values:

```env
DB_HOST=postgres.internal
DB_PORT=5432
DATABASE_URL=postgres://user:pass@${DB_HOST}:${DB_PORT}/myapp
```

Supports `${VAR:-default}` fallback syntax. Circular and forward references are detected and rejected. Use `--no-interpolate` to send raw `${VAR}` syntax.

### Filtering

Control which variables are sent:

```bash
# exclude public/non-secret vars
enseal share .env --exclude "^PUBLIC_|^NEXT_PUBLIC_"

# send only matching vars
enseal share .env --include "^DB_|^API_"

# skip .env parsing entirely (send raw file)
enseal share .env --no-filter
```

### Smart Receive

Output adapts to what was sent:

```bash
# .env payload -> writes to file
enseal receive CODE
ok: 14 secrets written to .env

# write to specific file
enseal receive CODE --output staging.env

# raw string -> prints to stdout (pipe-friendly)
enseal receive CODE
sk_live_abc123

# force clipboard
enseal receive CODE --clipboard
ok: copied to clipboard

# force stdout for any payload
enseal receive CODE --no-write

# receive from encrypted file drop (identity mode)
enseal receive ./staging.env.age
ok: signature verified, file decrypted
ok: 14 secrets written to .env
```

### Inject

Receive secrets and inject them directly as environment variables into a child process. Secrets never touch the filesystem.

```bash
# anonymous mode: inject via wormhole code
enseal inject 7-guitarist-revenge -- npm start

# identity mode: listen for incoming transfer on relay
enseal inject --listen --relay wss://relay.internal:4443 -- docker compose up

# from encrypted file drop
enseal inject ./staging.env.age -- python manage.py runserver
```

With `--listen`, the receiver connects to the relay and waits. The sender pushes with `enseal share .env --to alex --relay wss://relay.internal:4443` — no codes exchanged, zero coordination needed.

### .env Toolkit

Beyond sharing, enseal is a complete `.env` security toolkit:

```bash
# check: verify your .env has all required vars
enseal check
error: missing from .env (present in .env.example):
  JWT_SECRET, REDIS_URL

# diff: compare two .env files (keys only, never values)
enseal diff .env.development .env.staging
  + REDIS_CLUSTER_URL    (only in staging)
  - DEBUG                (only in development)

# redact: strip values for safe sharing of structure
enseal redact .env
  DATABASE_URL=<REDACTED>
  API_KEY=<REDACTED>
  PORT=<REDACTED>

# validate: check values against schema rules
enseal validate .env
  error: missing required: JWT_SECRET
  error: PORT value "abc" is not an integer
  ok: 11/14 variables passed validation

# template: generate .env.example with type hints
enseal template .env
  # DATABASE_URL=<postgres connection string>
  # API_KEY=<32+ character string>
  # PORT=<integer, 1024-65535>
```

### At-Rest Encryption

Encrypt `.env` files for safe git storage using age encryption:

```bash
# whole-file encryption
enseal encrypt .env
ok: .env encrypted in-place (14 variables, age key)

enseal decrypt .env

# per-variable: keys visible for diffing, values encrypted
enseal encrypt .env --per-var
# DB_HOST=ENC[age:abc123...]
# DB_PORT=ENC[age:def456...]

# multi-recipient: anyone on the team can decrypt
enseal encrypt .env --to sarah --to alex
```

### Identity & Key Management

```bash
# generate your keypair
enseal keys init

# share your public key with teammates
enseal keys export > my-key.pub

# import a teammate's key (shows fingerprint, prompts for confirmation)
enseal keys import sarah.pub

# list all trusted keys and aliases
enseal keys list

# show your key fingerprint (for out-of-band verification)
enseal keys fingerprint

# remove a trusted key
enseal keys remove sarah@company.com

# create aliases for convenience
enseal keys alias sarah sarah@company.com

# create groups for multi-recipient sharing
enseal keys group create backend-team
enseal keys group add backend-team sarah
enseal keys group add backend-team alex
enseal keys group list backend-team
enseal share .env --to backend-team

# delete a group
enseal keys group delete backend-team
```

### Self-Hosted Relay

Keep everything inside your network. The relay is stateless — it sees only ciphertext.

```bash
# Docker (one command)
docker run -d -p 4443:4443 enseal/relay

# Or as a binary
enseal serve --port 4443 --tls-cert cert.pem --tls-key key.pem

# Check relay health
enseal serve --health

# Clients point to your relay
enseal share .env --relay wss://relay.internal:4443
# or set it globally
export ENSEAL_RELAY=wss://relay.internal:4443
```

With identity mode and a self-hosted relay, sharing is fully codeless:

```bash
# receiver listens on the relay
enseal inject --listen --relay wss://relay.internal:4443 -- npm start

# sender pushes directly — no code generated
enseal share .env --to alex --relay wss://relay.internal:4443
ok: pushed to alex
```

### Schema Validation

Define rules in `.enseal.toml` at the project root:

```toml
[schema]
required = ["DATABASE_URL", "API_KEY", "JWT_SECRET"]

[schema.rules.DATABASE_URL]
pattern = "^postgres://"
description = "PostgreSQL connection string"

[schema.rules.PORT]
type = "integer"
range = [1024, 65535]

[schema.rules.API_KEY]
min_length = 32
```

Then validate:

```bash
enseal validate .env
```

Validation also runs automatically when receiving `.env` files — catching broken configs before they cause confusion.

### Environment Profiles

```bash
enseal share --env staging              # shares .env.staging
enseal validate --env production        # validates .env.production
enseal diff .env.development .env.production
```

## How It Works

### Anonymous Mode (Wormhole)

1. Sender encrypts the payload with `age`
2. A SPAKE2 key exchange establishes a shared secret via the relay
3. The encrypted payload transits through the relay
4. Recipient decrypts with the negotiated key
5. The channel is destroyed — single use, time-limited

The relay never sees plaintext. The wormhole code provides mutual authentication.

### Identity Mode (Public Key)

1. Sender encrypts with the recipient's `age` public key
2. Sender signs with their own `ed25519` key
3. Payload transits through relay, file drop, or wormhole
4. Recipient decrypts with their private key
5. Recipient verifies the sender's signature

Trust is based on which keys you've imported.

**Transport options in identity mode:**

| Transport | Flag | How it works |
|---|---|---|
| Wormhole (default) | `--to sarah` | Generates a code, like anonymous mode but with signing |
| Relay push | `--to sarah --relay URL` | Pushes to recipient's deterministic channel, no code |
| File drop | `--to sarah --output ./dir/` | Produces encrypted `.env.age` file, no network |

With relay push, the recipient listens with `enseal inject --listen --relay URL -- cmd` or receives the file drop with `enseal receive ./file.env.age`.

## Security Model

**Protected:**
- Secrets in transit (encrypted channel)
- Secrets in Slack/email history (ephemeral, no persistence)
- MITM attacks (SPAKE2 / public key auth)
- Malicious relay (E2E encryption, relay sees ciphertext only)
- Sender impersonation (identity mode: ed25519 signatures)
- Secrets on disk (inject mode: process memory only)
- Secrets in git (encrypt: at-rest encryption)

**Not protected:**
- Compromised endpoints (if the machine is owned, nothing helps)
- Key distribution (you trust the keys you import — no PKI, no CA)

## Configuration

Optional `.enseal.toml` in your project root:

```toml
[defaults]
relay = "wss://relay.internal.company.com:4443"
timeout = 600

[filter]
exclude = ["^PUBLIC_", "^NEXT_PUBLIC_", "^REACT_APP_"]

[identity]
default_recipient = "devops-team"

[schema]
required = ["DATABASE_URL", "API_KEY", "JWT_SECRET"]
```

## CLI Reference

```
CORE
  enseal share [<file>]              Send secrets (file, pipe, or --secret)
  enseal receive [<code|file>]       Receive secrets
  enseal inject [<code>] -- <cmd>    Inject secrets into a process
  enseal keys <subcommand>           Manage identity keys and aliases
  enseal serve                       Run self-hosted relay server

.ENV TOOLKIT
  enseal check [file]                Verify .env has all vars from .env.example
  enseal diff <file1> <file2>        Compare .env files (keys only)
  enseal redact <file>               Replace values with <REDACTED>
  enseal validate <file>             Validate against schema rules
  enseal template <file>             Generate .env.example with type hints

ENCRYPTION
  enseal encrypt <file>              Encrypt .env for git storage
  enseal decrypt <file>              Decrypt an encrypted .env
```

### `share` flags

```
--to <name>              Identity mode: encrypt to recipient (alias, group, or identity)
--output <dir>           File drop: write encrypted file (identity mode, no network)
--secret <value>         Inline secret (raw string or KEY=VALUE)
--label <name>           Human label for raw/piped secrets
--as <KEY>               Wrap raw input as KEY=<value>
--relay <url>            Use specific relay server (also: ENSEAL_RELAY)
--env <profile>          Environment profile (resolves to .env.<profile>)
--exclude <pattern>      Regex to exclude vars
--include <pattern>      Regex to include only matching vars
--no-filter              Send raw file, skip .env parsing
--no-interpolate         Don't resolve ${VAR} references before sending
--words <n>              Number of words in wormhole code (default: 2)
--timeout <seconds>      Channel expiry (default: 300)
--quiet / -q             Minimal output
```

### `receive` flags

```
--output <path>          Write to specific file
--clipboard              Copy to clipboard instead of stdout/file
--no-write               Print to stdout even for .env payloads
--relay <url>            Use specific relay server
--quiet / -q             Minimal output
```

### `inject` flags

```
--listen                 Listen for incoming identity-mode transfer (requires --relay)
--relay <url>            Use specific relay server (also: ENSEAL_RELAY)
--quiet / -q             Minimal output
```

### `keys` subcommands

```
enseal keys init                         Generate your keypair
enseal keys export                       Print your public key bundle
enseal keys import <file>                Import a colleague's public key
enseal keys list                         Show all trusted keys and aliases
enseal keys remove <identity>            Remove a trusted key
enseal keys fingerprint                  Show your key fingerprint
enseal keys alias <name> <identity>      Map short name to identity
enseal keys group create <name>          Create a named group
enseal keys group add <group> <id>       Add identity to group
enseal keys group remove <group> <id>    Remove identity from group
enseal keys group list [name]            List groups or group members
enseal keys group delete <name>          Delete a group
```

### `serve` flags

```
--port <port>            Listen port (default: 4443)
--bind <addr>            Bind address (default: 0.0.0.0)
--max-mailboxes <n>      Max concurrent channels (default: 100)
--channel-ttl <seconds>  Idle channel lifetime (default: 300)
--health                 Print server health check and exit
```

### `encrypt` / `decrypt` flags

```
--per-var                Per-variable encryption (keys visible, values encrypted)
--to <name>              Encrypt to specific recipients (multi-key)
```

### Global flags

```
--verbose / -v           Debug output (never prints secret values)
--quiet / -q             Minimal output (for scripting)
--config <path>          Path to .enseal.toml manifest
```

## Comparison

| | enseal | Slack DM | 1Password Share | dotenvx | croc |
|---|---|---|---|---|---|
| Zero setup | Yes | Yes | No | No | Yes |
| End-to-end encrypted | Yes | No | Yes | N/A | Yes |
| Ephemeral (no history) | Yes | No | Yes | N/A | Yes |
| .env aware | Yes | No | No | Yes | No |
| Process injection | Yes | No | No | Yes | No |
| Schema validation | Yes | No | No | No | No |
| At-rest encryption | Yes | N/A | N/A | Yes | No |
| Self-hostable relay | Yes | No | No | N/A | Yes |
| Raw string/pipe support | Yes | Yes | No | No | Yes |

## Roadmap

- **v0.1** — Core: share/receive, pipe/stdin, .env toolkit (check, diff, redact)
- **v0.2** — Identity mode: keys, aliases, `--to` flag
- **v0.3** — Inject command, self-hosted relay
- **v0.4** — Schema validation, templates, interpolation, profiles
- **v0.5** — At-rest encryption (encrypt/decrypt)
- **v1.0** — Groups, Helm chart, shell completions, docs

## License

MIT
