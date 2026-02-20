"""Puma (Delinea / Thycotic Secret Server) integration for medcred.

Provides a thin client for fetching secrets from an on-prem Secret Server
instance via the python-tss-sdk, and a set of CLI sub-commands that let you
pull those secrets directly into the medcred vault.

Credential resolution order
---------------------------
Puma service-account credentials are resolved in this order at runtime:

1. git credential store  — the primary source.  Backed by your OS keychain
   (macOS Keychain, Windows Credential Manager, Linux libsecret).  Store once:

       medcred puma store-credentials --url https://puma.corp.example.com --user svc_acct

2. Environment variables — override / one-off use:
       PUMA_URL        Base URL of the Secret Server
       PUMA_USER       Application account username
       PUMA_DOMAIN     Windows / AD domain (omit for basic auth)
       PUMA_PASSWORD   Application account password

   REQUESTS_CA_BUNDLE   Path to CA bundle .pem for self-signed TLS certs (optional)

Once authenticated, Puma is queried live for the secret — so rotating passwords
are always fetched fresh at call time, never cached locally.

Usage (CLI)
-----------
    medcred puma fetch 1234                  # fetch secret by ID
    medcred puma fetch --path "\\Folder\\Name"   # fetch by folder path
    medcred puma pull 1234                   # fetch and store in local vault
    medcred puma env 1234                    # print as KEY=VALUE exports
    medcred puma store-credentials           # save Puma creds in OS keychain via git
"""

from __future__ import annotations

import os
import subprocess
from typing import Annotated, Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
err = Console(stderr=True)

puma_app = typer.Typer(
    name="puma",
    help="Fetch secrets from Puma (Delinea Secret Server).",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


# ---------------------------------------------------------------------------
# git credential helpers
# ---------------------------------------------------------------------------


def _git_credential_get(url: str, username: str | None = None) -> tuple[str | None, str | None]:
    """Query the git credential store for (username, password) for *url*.

    Uses ``git credential fill`` which delegates to whichever credential helper
    is configured (OS keychain on macOS/Windows, libsecret on Linux, etc.).
    Returns ``(None, None)`` if git is unavailable or no match is found.
    """
    parsed = urlparse(url)
    lines = [f"protocol={parsed.scheme}", f"host={parsed.netloc}"]
    if username:
        lines.append(f"username={username}")
    lines.append("")  # git requires a trailing blank line

    try:
        result = subprocess.run(
            ["git", "credential", "fill"],
            input="\n".join(lines),
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None, None

    if result.returncode != 0:
        return None, None

    got_user: str | None = None
    got_pass: str | None = None
    for line in result.stdout.splitlines():
        if line.startswith("username="):
            got_user = line[len("username="):]
        elif line.startswith("password="):
            got_pass = line[len("password="):]

    return got_user, got_pass


def _git_credential_approve(url: str, username: str, password: str) -> bool:
    """Store *username* / *password* for *url* in the git credential store.

    Returns ``True`` on success, ``False`` if git is unavailable.
    """
    parsed = urlparse(url)
    credential_input = (
        f"protocol={parsed.scheme}\n"
        f"host={parsed.netloc}\n"
        f"username={username}\n"
        f"password={password}\n\n"
    )
    try:
        result = subprocess.run(
            ["git", "credential", "approve"],
            input=credential_input,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class PumaClient:
    """Thin wrapper around python-tss-sdk for Secret Server access."""

    def __init__(self) -> None:
        self._server = self._connect()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self):
        try:
            from delinea.secrets.server import (  # type: ignore[import-not-found]
                AccessTokenAuthorizer,
                DomainPasswordGrantAuthorizer,
                PasswordGrantAuthorizer,
                SecretServer,
            )
        except ImportError as exc:
            err.print(
                "[bold red]python-tss-sdk is not installed.[/bold red]\n"
                "Run:  [bold]pip install python-tss-sdk[/bold]"
            )
            raise typer.Exit(1) from exc

        base_url = _require_env("PUMA_URL")
        token = os.environ.get("PUMA_ACCESS_TOKEN")

        if token:
            authorizer = AccessTokenAuthorizer(token)
        else:
            # Primary: git credential store (works in scripts, notebooks, CI).
            # Override: explicit env vars (useful for one-off overrides).
            gc_user, gc_pass = _git_credential_get(base_url)
            user = os.environ.get("PUMA_USER") or gc_user
            password = os.environ.get("PUMA_PASSWORD") or gc_pass

            if gc_user and gc_pass and not os.environ.get("PUMA_PASSWORD"):
                err.print("[dim]Puma credentials loaded from git credential store.[/dim]")

            if not user:
                err.print(
                    "[bold red]No Puma credentials found.[/bold red]\n"
                    "Run: [bold]medcred puma store-credentials --url PUMA_URL --user USERNAME[/bold]\n"
                    "Or set [bold]PUMA_USER[/bold] and [bold]PUMA_PASSWORD[/bold] env vars."
                )
                raise typer.Exit(1)
            if not password:
                err.print(
                    "[bold red]No Puma password found.[/bold red]\n"
                    "Run: [bold]medcred puma store-credentials --url PUMA_URL --user USERNAME[/bold]\n"
                    "Or set [bold]PUMA_PASSWORD[/bold] env var."
                )
                raise typer.Exit(1)

            domain = os.environ.get("PUMA_DOMAIN")
            if domain:
                authorizer = DomainPasswordGrantAuthorizer(
                    base_url=base_url,
                    username=user,
                    domain=domain,
                    password=password,
                )
            else:
                authorizer = PasswordGrantAuthorizer(
                    base_url=base_url,
                    username=user,
                    password=password,
                )

        return SecretServer(base_url=base_url, authorizer=authorizer)

    # ------------------------------------------------------------------
    # Fetch helpers
    # ------------------------------------------------------------------

    def get_by_id(self, secret_id: int) -> dict:
        from delinea.secrets.server import SecretServerError  # type: ignore[import-not-found]

        try:
            from delinea.secrets.server import ServerSecret  # type: ignore[import-not-found]

            return ServerSecret(**self._server.get_secret(secret_id))
        except SecretServerError as exc:
            err.print(f"[bold red]Secret Server error:[/bold red] {exc}")
            raise typer.Exit(1) from exc

    def get_by_path(self, path: str) -> dict:
        from delinea.secrets.server import SecretServerError  # type: ignore[import-not-found]

        try:
            from delinea.secrets.server import ServerSecret  # type: ignore[import-not-found]

            return ServerSecret(**self._server.get_secret_by_path(path))
        except SecretServerError as exc:
            err.print(f"[bold red]Secret Server error:[/bold red] {exc}")
            raise typer.Exit(1) from exc


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        err.print(
            f"[bold red]Required environment variable [bold]{name}[/bold] is not set.[/bold red]"
        )
        raise typer.Exit(1)
    return val


def _secret_to_dict(secret) -> dict[str, str]:
    """Extract a flat {field_name: value} dict from a ServerSecret."""
    return {k: (v.value or "") for k, v in secret.fields.items()}


def _render_secret(secret, title: str = "Secret") -> None:
    fields = _secret_to_dict(secret)
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    for key, value in fields.items():
        key_lower = key.lower()
        if any(word in key_lower for word in ("password", "secret", "token", "key")):
            display = "••••••••••••"
        else:
            display = value
        table.add_row(key, display)

    console.print(Panel(table, title=f"[bold cyan]{title}[/bold cyan]", border_style="cyan", expand=False))


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------


@puma_app.command()
def fetch(
    secret_id: Annotated[Optional[int], typer.Argument(help="Secret ID.")] = None,
    path: Annotated[Optional[str], typer.Option("--path", "-p", help="Secret folder path.")] = None,
    show: Annotated[bool, typer.Option("--show", "-s", help="Reveal sensitive field values.")] = False,
) -> None:
    """Fetch a secret from Puma and display it."""
    if secret_id is None and path is None:
        err.print("[danger]Provide either a secret ID or --path.[/danger]")
        raise typer.Exit(1)

    client = PumaClient()

    if path:
        secret = client.get_by_path(path)
    else:
        secret = client.get_by_id(secret_id)  # type: ignore[arg-type]

    fields = _secret_to_dict(secret)
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    for key, value in fields.items():
        key_lower = key.lower()
        sensitive = any(word in key_lower for word in ("password", "secret", "token", "key"))
        display = value if (show or not sensitive) else "••••••••••••"
        table.add_row(key, display)

    title = path or f"Secret #{secret_id}"
    console.print(Panel(table, title=f"[bold cyan]{title}[/bold cyan]", border_style="cyan", expand=False))


@puma_app.command()
def pull(
    secret_id: Annotated[Optional[int], typer.Argument(help="Secret ID.")] = None,
    path: Annotated[Optional[str], typer.Option("--path", "-p", help="Secret folder path.")] = None,
    name: Annotated[Optional[str], typer.Option("--name", "-n", help="Override credential name in vault.")] = None,
    tags: Annotated[Optional[str], typer.Option("--tags", "-t", help="Comma-separated tags to apply.")] = None,
) -> None:
    """Fetch a secret from Puma and store it in the local medcred vault.

    Requires the vault to already be initialised ([bold]medcred init[/bold]).
    """
    from .models import Credential
    from .store import VaultStore, BadVaultError
    from .cli import _get_vault_path, _ask_password

    if secret_id is None and path is None:
        err.print("[danger]Provide either a secret ID or --path.[/danger]")
        raise typer.Exit(1)

    client = PumaClient()

    if path:
        secret = client.get_by_path(path)
        label = path.split("\\")[-1] if "\\" in (path or "") else path
    else:
        secret = client.get_by_id(secret_id)  # type: ignore[arg-type]
        label = f"puma-{secret_id}"

    fields = _secret_to_dict(secret)

    cred_name = name or label
    username = fields.get("Username") or fields.get("username") or None
    password = fields.get("Password") or fields.get("password") or None
    url = fields.get("URL") or fields.get("url") or None
    notes_parts = []
    for k, v in fields.items():
        if k.lower() not in ("username", "password", "url") and v:
            notes_parts.append(f"{k}: {v}")
    notes = "\n".join(notes_parts) or None

    tag_list = [t.strip() for t in tags.split(",")] if tags else ["puma"]

    store_path = _get_vault_path()
    store = VaultStore(store_path)
    if not store.exists():
        err.print("[danger]No vault found. Run [bold]medcred init[/bold] first.[/danger]")
        raise typer.Exit(1)

    master = _ask_password()
    try:
        vault = store.load(master)
    except (ValueError, BadVaultError) as exc:
        err.print(f"[danger]{exc}[/danger]")
        raise typer.Exit(1) from exc

    # Deduplicate
    existing = [c for c in vault.credentials.values() if c.name.lower() == cred_name.lower()]
    if existing:
        import typer as _typer
        from rich.prompt import Confirm

        overwrite = Confirm.ask(
            f"  Credential '[bold]{cred_name}[/bold]' already exists. Overwrite?",
            default=False,
            console=console,
        )
        if not overwrite:
            raise typer.Exit(0)
        del vault.credentials[existing[0].id]

    cred = Credential(
        name=cred_name,
        username=username,
        password=password,
        url=url,
        notes=notes,
        tags=tag_list,
    )
    vault.credentials[cred.id] = cred
    store.save(vault, master)

    console.print(f"[bold green]Stored '[bold]{cred_name}[/bold]' in vault.[/bold green]")


@puma_app.command()
def env(
    secret_id: Annotated[Optional[int], typer.Argument(help="Secret ID.")] = None,
    path: Annotated[Optional[str], typer.Option("--path", "-p", help="Secret folder path.")] = None,
    prefix: Annotated[str, typer.Option("--prefix", help="Variable name prefix.")] = "",
) -> None:
    """Print a secret's fields as shell export statements.

    Useful for sourcing credentials into a shell session:

    \\b
        eval $(medcred puma env 1234 --prefix DB_)
    """
    if secret_id is None and path is None:
        err.print("[danger]Provide either a secret ID or --path.[/danger]")
        raise typer.Exit(1)

    client = PumaClient()

    if path:
        secret = client.get_by_path(path)
    else:
        secret = client.get_by_id(secret_id)  # type: ignore[arg-type]

    for key, value in _secret_to_dict(secret).items():
        var = (prefix + key).upper().replace(" ", "_").replace("-", "_")
        # Use printf-style quoting — wrap in single quotes, escape embedded ones
        safe = value.replace("'", "'\\''")
        typer.echo(f"export {var}='{safe}'")


@puma_app.command("store-credentials")
def store_credentials(
    url: Annotated[Optional[str], typer.Option("--url", "-u", help="Puma server base URL.")] = None,
    user: Annotated[Optional[str], typer.Option("--user", help="Service account username.")] = None,
) -> None:
    """Save Puma service-account credentials in the git credential store.

    Credentials are stored in your OS keychain via the configured git
    credential helper and are retrieved automatically at runtime — no env
    vars needed in scripts or notebooks.

    \\b
    Example:
        medcred puma store-credentials \\
            --url https://puma.corp.example.com \\
            --user svc_medcred
    """
    from rich.prompt import Prompt

    puma_url = url or os.environ.get("PUMA_URL")
    if not puma_url:
        err.print(
            "[bold red]Provide --url or set PUMA_URL.[/bold red]"
        )
        raise typer.Exit(1)

    puma_user = user or os.environ.get("PUMA_USER")
    if not puma_user:
        puma_user = Prompt.ask("Puma username", console=console)

    puma_password = Prompt.ask("Puma password", password=True, console=console)

    ok = _git_credential_approve(puma_url, puma_user, puma_password)
    if ok:
        console.print(
            f"[bold green]Credentials for [bold]{puma_url}[/bold] stored in git credential store.[/bold green]\n"
            "[dim]medcred puma commands will now use them automatically.[/dim]"
        )
    else:
        err.print(
            "[bold red]Failed to store credentials.[/bold red]\n"
            "Ensure git is installed and a credential helper is configured.\n"
            "Quick setup:  [bold]git config --global credential.helper store[/bold]"
        )
        raise typer.Exit(1)
