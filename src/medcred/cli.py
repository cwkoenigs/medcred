"""medcred — beautiful, production-grade credential management CLI.

Commands
--------
  init      Initialise a new encrypted vault
  add       Add a credential
  get       Retrieve a credential (optionally copy password to clipboard)
  list      List all credentials in a rich table
  update    Update fields on an existing credential
  delete    Remove a credential
  search    Full-text search across all fields
  generate  Generate strong random passwords
  export    Dump vault to JSON or CSV (plaintext — handle with care)
  import    Load credentials from a JSON export
  info      Show vault metadata
  puma      Fetch secrets from Puma (Delinea Secret Server)
"""

from __future__ import annotations

import csv
import json
import os
import secrets
import string
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import __version__
from .models import Credential, Vault
from .puma import puma_app
from .store import BadVaultError, VaultStore

# ---------------------------------------------------------------------------
# App & consoles
# ---------------------------------------------------------------------------

_THEME = Theme(
    {
        "success": "bold green",
        "warning": "bold yellow",
        "danger": "bold red",
        "muted": "dim",
        "label": "cyan",
        "highlight": "bold white",
    }
)

console = Console(theme=_THEME)
err = Console(stderr=True, theme=_THEME)

app = typer.Typer(
    name="medcred",
    help="[bold cyan]medcred[/bold cyan] — secure, beautiful credential management.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
    rich_markup_mode="rich",
    add_completion=True,
)
app.add_typer(puma_app, name="puma")

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_PASSWORD_CHARS = string.ascii_letters + string.digits + r"!@#$%^&*()-_=+[]{}|;:,.<>?"


def _get_vault_path() -> Path:
    env = os.environ.get("MEDCRED_VAULT")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "medcred" / "vault.mc"


def _store() -> VaultStore:
    return VaultStore(_get_vault_path())


def _require_vault() -> VaultStore:
    store = _store()
    if not store.exists():
        err.print(
            "[danger]No vault found.[/danger] Run [bold]medcred init[/bold] first.",
        )
        raise typer.Exit(1)
    return store


def _ask_password(prompt: str = "Master password") -> str:
    return Prompt.ask(prompt, password=True, console=console)


def _unlock(store: VaultStore) -> tuple[Vault, str]:
    """Prompt for master password and return (vault, password)."""
    password = _ask_password()
    try:
        vault = store.load(password)
        return vault, password
    except ValueError as exc:
        err.print(f"[danger]{exc}[/danger]")
        raise typer.Exit(1) from exc
    except BadVaultError as exc:
        err.print(f"[danger]{exc}[/danger]")
        raise typer.Exit(1) from exc


def _make_password(length: int, no_symbols: bool = False) -> str:
    charset = string.ascii_letters + string.digits
    if not no_symbols:
        charset += r"!@#$%^&*()-_=+[]{}|;:,.<>?"
    return "".join(secrets.choice(charset) for _ in range(length))


def _find_one(vault: Vault, name: str) -> Credential:
    """Return the unique credential matching *name* (exact then partial)."""
    name_l = name.lower()
    exact = [c for c in vault.credentials.values() if c.name.lower() == name_l]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        err.print(f"[warning]Multiple exact matches for '{name}' — please be more specific.[/warning]")
        for c in exact:
            err.print(f"  • {c.name} ({c.id[:8]})")
        raise typer.Exit(1)

    partial = [c for c in vault.credentials.values() if name_l in c.name.lower()]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        err.print(f"[warning]Multiple partial matches for '{name}':[/warning]")
        for c in partial:
            err.print(f"  • {c.name}")
        raise typer.Exit(1)

    err.print(f"[danger]No credential found matching '[bold]{name}[/bold]'.[/danger]")
    raise typer.Exit(1)


def _render_credential(cred: Credential, *, show_password: bool = False) -> None:
    body = Text()

    def row(label: str, value: str, style: str = "highlight") -> None:
        body.append(f"  {label:<12}", style="label")
        body.append(value + "\n", style=style)

    if cred.username:
        row("Username", cred.username)
    if cred.password:
        row("Password", cred.password if show_password else "••••••••••••", style="bold green" if show_password else "muted")
    if cred.url:
        row("URL", cred.url, style="blue underline")
    if cred.notes:
        row("Notes", cred.notes, style="italic")
    if cred.tags:
        row("Tags", "  ".join(f"[yellow]#{t}[/yellow]" for t in cred.tags), style="")
    row("Created", cred.created_at.strftime("%Y-%m-%d %H:%M UTC"), style="muted")
    row("Updated", cred.updated_at.strftime("%Y-%m-%d %H:%M UTC"), style="muted")
    row("ID", cred.id[:8] + "…", style="muted")

    console.print(
        Panel(body, title=f"[bold cyan]{cred.name}[/bold cyan]", expand=False, border_style="cyan")
    )


def _render_table(creds: list[Credential], title: str = "Credentials") -> None:
    table = Table(
        title=title,
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=False,
        highlight=True,
        title_style="bold",
    )
    table.add_column("#", style="muted", justify="right", no_wrap=True)
    table.add_column("Name", style="bold white", min_width=16)
    table.add_column("Username", style="dim", min_width=14)
    table.add_column("URL", style="blue", max_width=35)
    table.add_column("Tags", style="yellow")
    table.add_column("Updated", style="muted", no_wrap=True)

    for i, c in enumerate(sorted(creds, key=lambda x: x.name.lower()), 1):
        table.add_row(
            str(i),
            c.name,
            c.username or "",
            c.url or "",
            " ".join(f"#{t}" for t in c.tags),
            c.updated_at.strftime("%Y-%m-%d"),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def init(
    vault: Annotated[
        Optional[Path],
        typer.Option("--vault", "-v", help="Custom vault file path.", show_default=False),
    ] = None,
) -> None:
    """Initialise a new encrypted vault."""
    if vault:
        os.environ["MEDCRED_VAULT"] = str(vault)

    store = _store()

    if store.exists():
        overwrite = Confirm.ask(
            "[warning]A vault already exists at this path. Overwrite?[/warning]",
            default=False,
            console=console,
        )
        if not overwrite:
            raise typer.Exit(0)

    console.print(
        Panel(
            "[bold]Welcome to medcred[/bold]\n"
            "[muted]Choose a strong master password — it cannot be recovered if lost.[/muted]",
            title="[bold cyan]Vault Initialisation[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    pw = Prompt.ask("  Master password", password=True, console=console)
    if not pw:
        err.print("[danger]Master password cannot be empty.[/danger]")
        raise typer.Exit(1)
    confirm = Prompt.ask("  Confirm password", password=True, console=console)
    if pw != confirm:
        err.print("[danger]Passwords do not match.[/danger]")
        raise typer.Exit(1)

    store.init(pw)
    console.print(f"\n[success]Vault created →[/success] [bold]{store.path}[/bold]")
    console.print("[muted]Keep your master password safe — it cannot be recovered.[/muted]")


@app.command()
def add(
    name: Annotated[str, typer.Argument(help="Unique name / label for this credential.")],
    username: Annotated[Optional[str], typer.Option("--username", "-u", help="Username or email.")] = None,
    url: Annotated[Optional[str], typer.Option("--url", help="Associated URL.")] = None,
    notes: Annotated[Optional[str], typer.Option("--notes", "-n", help="Free-form notes.")] = None,
    tags: Annotated[Optional[str], typer.Option("--tags", "-t", help="Comma-separated tags.")] = None,
    generate: Annotated[bool, typer.Option("--generate", "-g", help="Auto-generate a password.")] = False,
    length: Annotated[int, typer.Option("--length", "-l", help="Generated password length.")] = 20,
    no_symbols: Annotated[bool, typer.Option("--no-symbols", help="Exclude symbols from generated password.")] = False,
) -> None:
    """Add a new credential to the vault."""
    store = _require_vault()
    vault, master = _unlock(store)

    # Duplicate check
    if any(c.name.lower() == name.lower() for c in vault.credentials.values()):
        err.print(f"[danger]A credential named '[bold]{name}[/bold]' already exists.[/danger]")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]Adding[/bold cyan] [bold]{name}[/bold]\n")

    if username is None:
        username = Prompt.ask("  Username [muted](blank to skip)[/muted]", default="", console=console) or None
    if url is None:
        url = Prompt.ask("  URL      [muted](blank to skip)[/muted]", default="", console=console) or None

    if generate:
        cred_pw: Optional[str] = _make_password(length, no_symbols)
        console.print(f"  [muted]Generated:[/muted] [bold green]{cred_pw}[/bold green]")
    else:
        cred_pw = Prompt.ask("  Password [muted](blank to skip)[/muted]", password=True, default="", console=console) or None

    if notes is None:
        notes = Prompt.ask("  Notes    [muted](blank to skip)[/muted]", default="", console=console) or None

    tag_list = [t.strip() for t in tags.split(",")] if tags else []

    cred = Credential(
        name=name,
        username=username,
        password=cred_pw,
        url=url,
        notes=notes,
        tags=tag_list,
    )
    vault.credentials[cred.id] = cred
    store.save(vault, master)

    console.print(f"\n[success]Credential '[bold]{name}[/bold]' saved.[/success]")


@app.command()
def get(
    name: Annotated[str, typer.Argument(help="Credential name (exact or partial).")],
    show: Annotated[bool, typer.Option("--show", "-s", help="Display password in plain text.")] = False,
    copy: Annotated[bool, typer.Option("--copy", "-c", help="Copy password to clipboard.")] = False,
) -> None:
    """Retrieve a credential and display its details."""
    store = _require_vault()
    vault, _ = _unlock(store)
    cred = _find_one(vault, name)
    _render_credential(cred, show_password=show)

    if copy and cred.password:
        try:
            import pyperclip  # noqa: PLC0415

            pyperclip.copy(cred.password)
            console.print("[success]Password copied to clipboard.[/success]")
        except Exception:
            console.print("[warning]Could not access clipboard. Is pyperclip installed and configured?[/warning]")


@app.command("list")
def list_creds(
    tag: Annotated[Optional[str], typer.Option("--tag", "-t", help="Filter by tag.")] = None,
    search: Annotated[Optional[str], typer.Option("--search", "-s", help="Filter by name / URL substring.")] = None,
) -> None:
    """List all credentials in a formatted table."""
    store = _require_vault()
    vault, _ = _unlock(store)

    creds = list(vault.credentials.values())

    if tag:
        creds = [c for c in creds if tag.lower() in (t.lower() for t in c.tags)]
    if search:
        q = search.lower()
        creds = [
            c for c in creds
            if q in c.name.lower() or (c.url and q in c.url.lower())
        ]

    if not creds:
        console.print("[muted]No credentials match your query.[/muted]")
        return

    _render_table(creds, title=f"Credentials ({len(creds)} total)")


@app.command()
def update(
    name: Annotated[str, typer.Argument(help="Credential name (exact or partial).")],
    new_name: Annotated[Optional[str], typer.Option("--name", help="Rename the credential.")] = None,
    username: Annotated[Optional[str], typer.Option("--username", "-u", help="New username.")] = None,
    url: Annotated[Optional[str], typer.Option("--url", help="New URL.")] = None,
    notes: Annotated[Optional[str], typer.Option("--notes", "-n", help="New notes.")] = None,
    tags: Annotated[Optional[str], typer.Option("--tags", "-t", help="Replace tags (comma-separated).")] = None,
    generate: Annotated[bool, typer.Option("--generate", "-g", help="Auto-generate a new password.")] = False,
    length: Annotated[int, typer.Option("--length", "-l", help="Generated password length.")] = 20,
    no_symbols: Annotated[bool, typer.Option("--no-symbols", help="Exclude symbols from generated password.")] = False,
) -> None:
    """Update an existing credential."""
    store = _require_vault()
    vault, master = _unlock(store)
    cred = _find_one(vault, name)

    changed = False

    if new_name and new_name != cred.name:
        cred.name = new_name
        changed = True
    if username is not None:
        cred.username = username or None
        changed = True
    if url is not None:
        cred.url = url or None
        changed = True
    if notes is not None:
        cred.notes = notes or None
        changed = True
    if tags is not None:
        cred.tags = [t.strip() for t in tags.split(",")]
        changed = True

    if generate:
        cred.password = _make_password(length, no_symbols)
        console.print(f"  [muted]New password:[/muted] [bold green]{cred.password}[/bold green]")
        changed = True
    else:
        new_pw = Prompt.ask(
            "  New password [muted](blank to keep current)[/muted]",
            password=True,
            default="",
            console=console,
        )
        if new_pw:
            cred.password = new_pw
            changed = True

    if not changed:
        console.print("[muted]No changes made.[/muted]")
        return

    cred.touch()
    store.save(vault, master)
    console.print(f"[success]Credential '[bold]{cred.name}[/bold]' updated.[/success]")


@app.command()
def delete(
    name: Annotated[str, typer.Argument(help="Credential name (exact or partial).")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt.")] = False,
) -> None:
    """Permanently delete a credential."""
    store = _require_vault()
    vault, master = _unlock(store)
    cred = _find_one(vault, name)

    if not yes:
        confirmed = Confirm.ask(
            f"  Delete '[bold]{cred.name}[/bold]'? [muted]This cannot be undone.[/muted]",
            default=False,
            console=console,
        )
        if not confirmed:
            raise typer.Exit(0)

    del vault.credentials[cred.id]
    store.save(vault, master)
    console.print(f"[danger]Credential '[bold]{cred.name}[/bold]' deleted.[/danger]")


@app.command()
def search(
    query: Annotated[str, typer.Argument(help="Search term (matches name, username, URL, notes, tags).")],
) -> None:
    """Search credentials across all fields."""
    store = _require_vault()
    vault, _ = _unlock(store)

    q = query.lower()
    results = [
        c
        for c in vault.credentials.values()
        if q in c.name.lower()
        or (c.username and q in c.username.lower())
        or (c.url and q in c.url.lower())
        or (c.notes and q in c.notes.lower())
        or any(q in t.lower() for t in c.tags)
    ]

    if not results:
        console.print(f"[muted]No results for '[bold]{query}[/bold]'.[/muted]")
        return

    _render_table(results, title=f"Search: {query}  ({len(results)} match{'es' if len(results) != 1 else ''})")


@app.command()
def generate(
    length: Annotated[int, typer.Option("--length", "-l", help="Password length.")] = 20,
    count: Annotated[int, typer.Option("--count", "-c", help="Number of passwords to generate.")] = 1,
    no_symbols: Annotated[bool, typer.Option("--no-symbols", help="Exclude symbols.")] = False,
    copy: Annotated[bool, typer.Option("--copy", help="Copy first password to clipboard.")] = False,
) -> None:
    """Generate one or more strong random passwords."""
    passwords = [_make_password(length, no_symbols) for _ in range(count)]

    if count == 1:
        console.print(
            Panel(
                f"[bold green]{passwords[0]}[/bold green]",
                title=f"[bold]Generated password ({length} chars)[/bold]",
                border_style="green",
                expand=False,
            )
        )
    else:
        console.print(f"\n[bold]Generated {count} passwords ({length} chars each)[/bold]\n")
        for i, pw in enumerate(passwords, 1):
            console.print(f"  [muted]{i:>3}.[/muted]  [bold green]{pw}[/bold green]")
        console.print()

    if copy:
        try:
            import pyperclip  # noqa: PLC0415

            pyperclip.copy(passwords[0])
            console.print("[success]First password copied to clipboard.[/success]")
        except Exception:
            console.print("[warning]Clipboard unavailable.[/warning]")


@app.command("export")
def export_cmd(
    output: Annotated[Path, typer.Option("--output", "-o", help="Output file path.")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="Output format: json or csv.")] = "json",
) -> None:
    """Export credentials to a file (plaintext — handle with care)."""
    store = _require_vault()
    vault, _ = _unlock(store)

    console.print(
        "[warning]WARNING:[/warning] The exported file will contain [bold]plaintext[/bold] credentials."
    )
    if not Confirm.ask("  Continue?", default=False, console=console):
        raise typer.Exit(0)

    rows = [
        {
            "name": c.name,
            "username": c.username or "",
            "password": c.password or "",
            "url": c.url or "",
            "notes": c.notes or "",
            "tags": ",".join(c.tags),
        }
        for c in vault.credentials.values()
    ]

    if fmt == "json":
        output.write_text(json.dumps(rows, indent=2))
    elif fmt == "csv":
        with output.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    else:
        err.print(f"[danger]Unknown format '{fmt}'. Use json or csv.[/danger]")
        raise typer.Exit(1)

    os.chmod(output, 0o600)
    console.print(
        f"\n[success]Exported {len(rows)} credential(s) →[/success] [bold]{output}[/bold]"
    )


@app.command("import")
def import_cmd(
    source: Annotated[Path, typer.Argument(help="JSON file to import (from 'medcred export').")],
) -> None:
    """Import credentials from a JSON export file."""
    if not source.exists():
        err.print(f"[danger]File not found: {source}[/danger]")
        raise typer.Exit(1)

    store = _require_vault()
    vault, master = _unlock(store)

    try:
        data: list[dict] = json.loads(source.read_text())
    except json.JSONDecodeError as exc:
        err.print(f"[danger]Invalid JSON: {exc}[/danger]")
        raise typer.Exit(1) from exc

    added = skipped = 0
    existing_names = {c.name.lower() for c in vault.credentials.values()}

    for item in data:
        name = item.get("name", "").strip()
        if not name:
            skipped += 1
            continue
        if name.lower() in existing_names:
            console.print(f"  [muted]Skipping duplicate:[/muted] {name}")
            skipped += 1
            continue
        cred = Credential(
            name=name,
            username=item.get("username") or None,
            password=item.get("password") or None,
            url=item.get("url") or None,
            notes=item.get("notes") or None,
            tags=[t for t in (item.get("tags") or "").split(",") if t],
        )
        vault.credentials[cred.id] = cred
        existing_names.add(name.lower())
        added += 1

    store.save(vault, master)
    console.print(
        f"[success]Import complete:[/success] {added} added, {skipped} skipped."
    )


@app.command()
def info() -> None:
    """Show vault metadata and location."""
    store = _store()
    path = store.path

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Version", __version__)
    table.add_row("Vault path", str(path))
    table.add_row("Vault exists", "[green]yes[/green]" if path.exists() else "[red]no[/red]")

    if path.exists():
        stat = path.stat()
        size_kb = stat.st_size / 1024
        table.add_row("Vault size", f"{size_kb:.1f} KB")

        vault, _ = _unlock(_require_vault())
        table.add_row("Credentials", str(len(vault.credentials)))

    console.print(Panel(table, title="[bold cyan]medcred info[/bold cyan]", border_style="cyan", expand=False))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app()


if __name__ == "__main__":
    main()
