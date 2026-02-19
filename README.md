# medcred

A beautiful, production-grade credential management CLI for the command line.

- **Encrypted vault** — PBKDF2-HMAC-SHA256 key derivation + Fernet (AES-128-CBC + HMAC) encryption
- **Rich terminal UI** — tables, panels, colour, clipboard integration
- **Puma integration** — fetch secrets from Delinea / Thycotic Secret Server
- **Single binary** — installable via pip, no daemon required

---

## Installation

```bash
pip install -e .                     # local dev
pip install -e ".[puma]"             # + Delinea Secret Server support
pip install -e ".[dev]"              # + test dependencies
```

---

## Quick start

```bash
# 1. Initialise an encrypted vault
medcred init

# 2. Add credentials interactively
medcred add github --username alice@example.com --tags dev,code

# 3. Generate and store a strong password automatically
medcred add myapp --generate --length 24

# 4. List everything
medcred list

# 5. Retrieve and copy to clipboard
medcred get github --copy

# 6. Search across all fields
medcred search alice

# 7. Generate a standalone password (no vault needed)
medcred generate --length 32 --count 5
```

---

## Commands

| Command | Description |
|---------|-------------|
| `init` | Initialise a new encrypted vault |
| `add <name>` | Add a credential |
| `get <name>` | Display a credential (`--show` to reveal password, `--copy` for clipboard) |
| `list` | List all credentials (`--tag`, `--search` for filtering) |
| `update <name>` | Update fields on a credential |
| `delete <name>` | Delete a credential |
| `search <query>` | Full-text search (name, username, URL, notes, tags) |
| `generate` | Generate strong random passwords |
| `export` | Dump vault to JSON or CSV (plaintext) |
| `import <file>` | Load credentials from a JSON export |
| `info` | Show vault path, size, and credential count |
| `puma fetch` | Display a Puma secret |
| `puma pull` | Import a Puma secret into the local vault |
| `puma env` | Print a secret's fields as shell export statements |

---

## Vault location

Default: `~/.local/share/medcred/vault.mc` (Linux/macOS), `%APPDATA%\medcred\vault.mc` (Windows).

Override with the `MEDCRED_VAULT` environment variable:

```bash
export MEDCRED_VAULT=/path/to/my/vault.mc
```

---

## Puma (Delinea Secret Server) integration

Install the extra dependency:

```bash
pip install -e ".[puma]"
```

Set environment variables (use a `.env` file or your devcontainer setup):

```bash
export PUMA_URL=https://puma.corp.example.com
export PUMA_USER=svc-medcred                  # application account
export PUMA_DOMAIN=CORP                        # omit for basic auth
export PUMA_PASSWORD=...
# Optional — path to CA bundle for self-signed certs
export REQUESTS_CA_BUNDLE=/path/to/ca.pem
```

```bash
# Display secret 1234 (passwords masked)
medcred puma fetch 1234

# Display with values revealed
medcred puma fetch 1234 --show

# Fetch by folder path
medcred puma fetch --path '\DataScience\postgres-prod'

# Pull into local vault
medcred puma pull 1234 --name postgres-prod --tags db,prod

# Source credentials into your shell
eval $(medcred puma env 1234 --prefix DB_)
```

> **Best practice:** request a dedicated application account from IT/Security
> that is scoped only to the secrets your scripts need. App accounts do not
> count against user licensing and cannot log into the Secret Server UI.

---

## Security notes

- Vault files are written with `0o600` permissions (owner read/write only).
- Key derivation uses 600 000 PBKDF2-HMAC-SHA256 iterations.
- The master password is never stored anywhere; losing it means losing vault access.
- Export files are plaintext — treat them like passwords and delete after use.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```
