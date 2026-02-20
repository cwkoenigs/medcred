"""medcred — beautiful, secure credential management for the command line."""

__version__ = "0.1.0"


def get_creds(secret, field: str = "Password") -> str:
    """Fetch a credential value from Puma — the one-liner for scripts and notebooks.

    Uses your stored Puma service-account credentials (from the git credential
    store) to authenticate, then returns the requested field value live from
    Puma. Rotating passwords are always fresh — nothing is cached locally.

    Args:
        secret: Puma secret path (str) or secret ID (int).
        field:  Field name to return. Defaults to ``"Password"``.

    Returns:
        The field value as a plain string.

    Raises:
        KeyError: If *field* is not present in the fetched secret.
        SystemExit: If Puma credentials are missing or the fetch fails.

    Example::

        from medcred import get_creds

        password = get_creds(r"\\Databases\\Snowflake\\prod")
        password = get_creds(1234)                # by secret ID
        username = get_creds(1234, field="Username")
    """
    from .puma import PumaClient, _secret_to_dict

    client = PumaClient()
    secret_obj = client.get_by_id(secret) if isinstance(secret, int) else client.get_by_path(secret)
    fields = _secret_to_dict(secret_obj)

    if field in fields:
        return fields[field]
    field_lower = field.lower()
    for k, v in fields.items():
        if k.lower() == field_lower:
            return v
    raise KeyError(f"Field {field!r} not found in secret. Available fields: {list(fields.keys())}")
