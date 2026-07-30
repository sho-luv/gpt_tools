from __future__ import annotations

import shlex
import uuid
from contextlib import closing
from typing import Annotated

import typer
from impacket.ldap.ldap import LDAPSessionError
from rich.console import Console

from goldengmsa_crypto import parse_sid
from goldengmsa_ldap import Credentials, DirectorySession
from goldengmsa_options import AesKey, DcHost, DcIp, Hashes, Kerberos, NoPass, Target
from goldengmsa_readers import PrincipalRecord, ReaderSet


def readers(
    target: Target,
    sid: Annotated[str | None, typer.Option(help="Only inspect this gMSA SID.")] = None,
    guid: Annotated[uuid.UUID | None, typer.Option(help="Only inspect this KDS root-key GUID.")] = None,
    domain: Annotated[str | None, typer.Option(help="Domain to query.")] = None,
    hashes: Hashes = None,
    no_pass: NoPass = False,
    kerberos: Kerberos = False,
    aes_key: AesKey = None,
    dc_ip: DcIp = None,
    dc_host: DcHost = None,
    expand_groups: Annotated[
        bool,
        typer.Option("--expand-groups/--no-expand-groups", help="Resolve nested group members."),
    ] = True,
) -> None:
    try:
        if sid is not None:
            parse_sid(sid)
        credentials = Credentials.parse(target, hashes, no_pass, aes_key, kerberos)
        with closing(DirectorySession.connect(credentials, domain or credentials.domain, dc_ip, dc_host)) as session:
            reader_sets = session.find_reader_sets(sid, guid, expand_groups=expand_groups)
    except OSError as error:
        raise typer.BadParameter(f"LDAP connection failed: {error.strerror or error}") from error
    except (LDAPSessionError, LookupError, ValueError) as error:
        raise typer.BadParameter(f"LDAP query failed: {error}") from error
    _print_reader_sets(reader_sets, credentials, dc_ip, dc_host, domain or credentials.domain)


def _print_reader_sets(
    reader_sets: list[ReaderSet],
    credentials: Credentials,
    dc_ip: str | None,
    dc_host: str | None,
    query_domain: str,
) -> None:
    console = Console(markup=False)
    endpoint = dc_host or dc_ip or credentials.target_host or query_domain
    for secret, title in (
        ("gMSA managed password", "Managed-password readers"),
        ("KDS root key", "KDS root-key readers"),
    ):
        matching_sets = [reader_set for reader_set in reader_sets if reader_set.secret == secret]
        if not matching_sets:
            continue
        console.print(f"\n{title}")
        console.print("-" * len(title))
        for reader_set in matching_sets:
            console.print(f"Target: {reader_set.target}")
            _print_principals(console, reader_set)

    root_key_sets = [reader_set for reader_set in reader_sets if reader_set.secret == "KDS root key"]
    candidates = [
        (reader_set, principal)
        for reader_set in root_key_sets
        for principal in reader_set.readers
        if principal.kind in {"user", "computer"} and principal.enabled is not False
    ]
    if not candidates:
        return
    title = "Possible pass-the-hash authentication"
    console.print(f"\n{title}")
    console.print("-" * len(title))
    console.print("Verify effective access before use.")
    for reader_set, principal in candidates:
        account = f"{principal.domain}/{principal.name}"
        auth_target = f"{account}@{endpoint}" if endpoint else account
        command = shlex.join(
            [
                "./goldengmsa.py",
                "kdsinfo",
                auth_target,
                "-hashes",
                ":<NTHASH>",
                "--guid",
                reader_set.target,
                "--show-secrets",
            ],
        )
        console.print(f"  {command}", soft_wrap=True)


def _print_principals(console: Console, reader_set: ReaderSet) -> None:
    if not reader_set.readers:
        console.print("  No readable allow ACEs found.")
        return
    direct = [principal for principal in reader_set.readers if principal.via is None]
    derived = [principal for principal in reader_set.readers if principal.via is not None]
    for principal in direct:
        _print_principal(console, principal, "direct")
        for member in derived:
            if member.via == principal.name:
                _print_principal(console, member, "group-derived", indent="  ")
    direct_names = {principal.name for principal in direct}
    for principal in derived:
        if principal.via not in direct_names:
            _print_principal(console, principal, f"group-derived via {principal.via}")


def _print_principal(
    console: Console,
    principal: PrincipalRecord,
    source: str,
    *,
    indent: str = "",
) -> None:
    account = f"{principal.domain}\\{principal.name}" if principal.domain else principal.name
    kind = principal.kind if principal.enabled is not False else f"{principal.kind} (disabled)"
    console.print(f"{indent}{account:<38} {kind:<20} {source}")
