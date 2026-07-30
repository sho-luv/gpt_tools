from __future__ import annotations

import base64
import uuid
from contextlib import closing
from dataclasses import dataclass
from typing import Annotated

import typer
from impacket.ldap.ldap import LDAPSessionError

from goldengmsa_cli_support import _credentials, _decode_base64, _print_command, console
from goldengmsa_crypto import BlobParseError, ManagedPasswordId, parse_sid
from goldengmsa_ldap import DirectorySession, GmsaRecord
from goldengmsa_options import AesKey, DcHost, DcIp, Hashes, Kerberos, NoPass, Target


@dataclass(frozen=True, slots=True)
class GmsaComputeInput:
    account: str | None
    sid: str
    password_id_blob: str
    root_key_guid: uuid.UUID


def _compute_input(record: GmsaRecord) -> GmsaComputeInput:
    password_id = ManagedPasswordId.from_bytes(record.password_id)
    return GmsaComputeInput(
        account=record.name,
        sid=record.sid,
        password_id_blob=base64.b64encode(record.password_id).decode("ascii"),
        root_key_guid=uuid.UUID(bytes_le=password_id.identifier),
    )


def _explicit_compute_input(sid: str, pwdid: str) -> GmsaComputeInput:
    parse_sid(sid)
    password_id = ManagedPasswordId.from_bytes(_decode_base64(pwdid, "--pwdid"))
    return GmsaComputeInput(
        account=None,
        sid=sid,
        password_id_blob=pwdid,
        root_key_guid=uuid.UUID(bytes_le=password_id.identifier),
    )


def kdsinfo(
    target: Target,
    guid: Annotated[uuid.UUID | None, typer.Option(help="Only return this KDS root key.")] = None,
    sid: Annotated[str | None, typer.Option(help="Explicit gMSA SID for the offline compute command.")] = None,
    pwdid: Annotated[
        str | None,
        typer.Option(help="Explicit Base64 managed password ID for the offline compute command."),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option(help="Domain containing gMSAs to discover; defaults to the authentication domain."),
    ] = None,
    forest: Annotated[str | None, typer.Option(help="Forest DNS domain used for the KDS root-key query.")] = None,
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
        explicit_input = _explicit_compute_input(sid, pwdid) if sid is not None and pwdid is not None else None
    except (BlobParseError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    if guid is not None and explicit_input is not None and guid != explicit_input.root_key_guid:
        raise typer.BadParameter("--guid does not match the root key GUID encoded in --pwdid")

    requested_guid = guid or (explicit_input.root_key_guid if explicit_input is not None else None)
    credentials = _credentials(target, hashes, no_pass, aes_key, kerberos)
    discovery_domain = domain or credentials.domain
    try:
        with closing(DirectorySession.connect(credentials, forest or credentials.domain, dc_ip, dc_host)) as session:
            root_keys = session.find_root_keys(requested_guid)
        if requested_guid is not None and not root_keys:
            raise LookupError(f"no KDS root key found for GUID {requested_guid}")
        if explicit_input is not None:
            compute_inputs = (explicit_input,)
        else:
            with closing(DirectorySession.connect(credentials, discovery_domain, dc_ip, dc_host)) as session:
                gmsa_records = session.find_gmsas()
            compute_inputs = tuple(_compute_input(record) for record in gmsa_records)
        for root_key in root_keys:
            encoded_root_key = base64.b64encode(root_key.root_key.to_bytes()).decode("ascii")
            console.print(f"Root key GUID (reference): {root_key.identifier}")
            console.print(f"KDS key for compute (--kdskey): {encoded_root_key}", soft_wrap=True)
            matches = tuple(item for item in compute_inputs if item.root_key_guid == root_key.identifier)
            if not matches:
                console.print(
                    f"\nNo gMSAs in {discovery_domain} reference KDS root key {root_key.identifier}; "
                    "use --domain for another domain or supply --sid/--pwdid.",
                )
            for item in matches:
                if item.account is not None:
                    console.print(f"\nMatching gMSA: {item.account}")
                console.print(f"gMSA SID for compute (--sid): {item.sid}")
                console.print(
                    f"Managed password ID for compute (--pwdid): {item.password_id_blob}",
                    soft_wrap=True,
                )
                _print_command(
                    "Offline compute command:",
                    ["./goldengmsa.py", "compute"],
                    [
                        ("--sid", item.sid),
                        ("--kdskey", encoded_root_key),
                        ("--pwdid", item.password_id_blob),
                        ("--show-secrets", None),
                    ],
                )
            console.print("-" * 46)
    except OSError as error:
        raise typer.BadParameter(f"LDAP connection failed: {error.strerror or error}") from error
    except (BlobParseError, LDAPSessionError, LookupError, ValueError) as error:
        raise typer.BadParameter(f"LDAP query failed: {error}") from error
