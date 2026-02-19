"""Puma (Delinea / Thycotic Secret Server) integration for medcred.

Provides a thin client for fetching secrets from an on-prem Secret Server
instance via the python-tss-sdk, and a set of CLI sub-commands that let you
pull those secrets directly into the medcred vault.

Environment variables
---------------------
PUMA_URL        Base URL of the Secret Server (e.g. https://puma.corp.example.com)
PUMA_USER       Application account username
PUMA_DOMAIN     Windows / AD domain for domain auth (omit for basic auth)
PUMA_PASSWORD   Application account password
REQUESTS_CA_BUNDLE   Path to CA bundle .pem for self-signed TLS certs (optional)

Usage (CLI)
-----------
    medcred puma fetch 1234                  # fetch secret by ID
    medcred puma fetch --path "\\Folder\\Name"   # fetch by folder path
    medcred puma pull 1234                   # fetch and store in local vault
    medcred puma env 1234                    # print as KEY=VALUE exports
"""

from __future__ import annotations

import os
from typing import Annotated, Optional

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
            user = _require_env("PUMA_USER")
            password = _require_env("PUMA_PASSWORD")
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
