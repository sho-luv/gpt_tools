from __future__ import annotations

import base64
import binascii
import shlex

import typer
from rich.console import Console

from goldengmsa_ldap import Credentials

console = Console()


def _decode_base64(value: str, option_name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise typer.BadParameter(f"{option_name} must be valid Base64") from error


def _credentials(
    target: str,
    hashes: str | None,
    no_pass: bool,
    aes_key: str | None,
    kerberos: bool,
) -> Credentials:
    try:
        return Credentials.parse(target, hashes, no_pass, aes_key, kerberos)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="target") from error


def _print_command(
    title: str,
    command: list[str],
    options: list[tuple[str, str | None]],
) -> None:
    lines = [shlex.join(command)]
    lines.extend(f"  {flag}" if value is None else f"  {flag} {shlex.quote(value)}" for flag, value in options)
    console.print(f"\n{title}")
    console.print(" \\\n".join(lines), soft_wrap=True)
