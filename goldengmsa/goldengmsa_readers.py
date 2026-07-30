from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Literal

from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import LDAP_SID

from goldengmsa_acl import ROOT_KEY_DATA_GUID, reader_sids
from goldengmsa_crypto import parse_sid

PrincipalKind = Literal["user", "computer", "group", "well-known", "unresolved"]

_WELL_KNOWN = {
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
}


@dataclass(frozen=True, slots=True)
class PrincipalRecord:
    sid: str
    name: str
    domain: str
    kind: PrincipalKind
    distinguished_name: str
    enabled: bool | None
    via: str | None = None


@dataclass(frozen=True, slots=True)
class ReaderSet:
    secret: str
    target: str
    readers: tuple[PrincipalRecord, ...]


class ReaderDiscovery:
    def __init__(self, connection: ldap.LDAPConnection) -> None:
        self._connection = connection

    def find(
        self,
        sid: str | None,
        identifier: uuid.UUID | None,
        expand_groups: bool,
    ) -> list[ReaderSet]:
        results = self._find_gmsa_readers(sid, expand_groups) if sid is not None or identifier is None else []
        if identifier is not None or sid is None:
            results.extend(self._find_root_key_readers(identifier, expand_groups))
        return results

    def _find_gmsa_readers(self, sid: str | None, expand_groups: bool) -> list[ReaderSet]:
        search_filter = "(objectCategory=msDS-GroupManagedServiceAccount)"
        if sid is not None:
            search_filter = f"(&{search_filter}(objectSid={parse_sid(sid).formatCanonical()}))"
        entries = self._search(
            search_filter,
            ["sAMAccountName", "objectSid", "msDS-GroupMSAMembership"],
        )
        results: list[ReaderSet] = []
        for entry in entries:
            attributes = _attribute_map(entry)
            account_sid = LDAP_SID(_required(attributes, "objectsid")).formatCanonical()
            target = f"{_text(attributes, 'samaccountname')} ({account_sid})"
            descriptor = attributes.get("msds-groupmsamembership")
            readers = () if descriptor is None else self._resolve_readers(descriptor, expand_groups)
            results.append(ReaderSet("gMSA managed password", target, readers))
        return results

    def _find_root_key_readers(
        self,
        identifier: uuid.UUID | None,
        expand_groups: bool,
    ) -> list[ReaderSet]:
        search_filter = "(objectClass=msKds-ProvRootKey)"
        if identifier is not None:
            search_filter = f"(&{search_filter}(cn={identifier}))"
        entries = self._search(
            search_filter,
            ["cn", "nTSecurityDescriptor"],
            search_base=self._configuration_naming_context(),
            include_dacl=True,
        )
        results: list[ReaderSet] = []
        for entry in entries:
            attributes = _attribute_map(entry)
            descriptor = _required(attributes, "ntsecuritydescriptor")
            readers = self._resolve_readers(
                descriptor,
                expand_groups,
                confidential=True,
                object_type=ROOT_KEY_DATA_GUID,
            )
            results.append(ReaderSet("KDS root key", _text(attributes, "cn"), readers))
        return results

    def _resolve_readers(
        self,
        descriptor: bytes,
        expand_groups: bool,
        *,
        confidential: bool = False,
        object_type: uuid.UUID | None = None,
    ) -> tuple[PrincipalRecord, ...]:
        principals: list[PrincipalRecord] = []
        for sid in reader_sids(descriptor, confidential=confidential, object_type=object_type):
            principal = self._resolve_sid(sid)
            principals.append(principal)
            if expand_groups and principal.kind == "group":
                principals.extend(
                    replace(member, via=principal.name) for member in self._expand_group(principal.distinguished_name)
                )
        return tuple({(item.sid, item.via): item for item in principals}.values())

    def _resolve_sid(self, sid: str) -> PrincipalRecord:
        entries = self._search(
            f"(objectSid={sid})",
            ["cn", "sAMAccountName", "objectSid", "objectClass", "distinguishedName", "userAccountControl"],
        )
        if not entries:
            name = _WELL_KNOWN.get(sid, sid)
            kind: PrincipalKind = "well-known" if sid in _WELL_KNOWN else "unresolved"
            return PrincipalRecord(sid, name, "", kind, "", None)
        return _principal_record(entries[0], sid)

    def _expand_group(self, distinguished_name: str) -> list[PrincipalRecord]:
        escaped_dn = _escape_filter(distinguished_name)
        entries = self._search(
            f"(&(memberOf:1.2.840.113556.1.4.1941:={escaped_dn})"
            "(|(objectClass=user)(objectClass=computer)(objectClass=foreignSecurityPrincipal)))",
            ["cn", "sAMAccountName", "objectSid", "objectClass", "distinguishedName", "userAccountControl"],
        )
        return [_principal_record(entry) for entry in entries]

    def _configuration_naming_context(self) -> str:
        entries = self._search(
            "(objectClass=*)",
            ["configurationNamingContext"],
            search_base="",
            scope=ldapasn1.Scope("baseObject"),
            paged=False,
        )
        if not entries:
            raise LookupError("RootDSE did not return configurationNamingContext")
        return _text(_attribute_map(entries[0]), "configurationnamingcontext")

    def _search(
        self,
        search_filter: str,
        attributes: list[str],
        *,
        search_base: str | None = None,
        scope: ldapasn1.Scope | None = None,
        paged: bool = True,
        include_dacl: bool = False,
    ) -> list[ldapasn1.SearchResultEntry]:
        controls: list[ldapasn1.Control] = []
        if paged:
            controls.append(ldapasn1.SimplePagedResultsControl(criticality=True, size=1000))
        if include_dacl:
            controls.append(ldapasn1.SDFlagsControl(criticality=True, flags=0x04))
        response = self._connection.search(
            searchBase=search_base,
            scope=scope,
            searchFilter=search_filter,
            attributes=attributes,
            searchControls=controls or None,
        )
        return [entry for entry in response if isinstance(entry, ldapasn1.SearchResultEntry)]


def _principal_record(entry: ldapasn1.SearchResultEntry, fallback_sid: str = "") -> PrincipalRecord:
    attributes = _attribute_map(entry)
    classes = {value.decode("utf-8").lower() for value in _attribute_values(entry, "objectclass")}
    if "group" in classes:
        kind: PrincipalKind = "group"
    elif "computer" in classes:
        kind = "computer"
    elif "user" in classes:
        kind = "user"
    else:
        kind = "unresolved"
    distinguished_name = _text(attributes, "distinguishedname")
    sid = LDAP_SID(_required(attributes, "objectsid")).formatCanonical() if "objectsid" in attributes else fallback_sid
    uac = int(attributes.get("useraccountcontrol", b"0"))
    enabled = None if kind in {"group", "unresolved"} else not bool(uac & 0x02)
    encoded_name = attributes.get("samaccountname", attributes.get("cn", sid.encode()))
    return PrincipalRecord(
        sid,
        encoded_name.decode("utf-8"),
        _domain_from_dn(distinguished_name),
        kind,
        distinguished_name,
        enabled,
    )


def _attribute_map(entry: ldapasn1.SearchResultEntry) -> Mapping[str, bytes]:
    return {
        str(attribute["type"]).lower(): attribute["vals"][0].asOctets()
        for attribute in entry["attributes"]
        if attribute["vals"]
    }


def _attribute_values(entry: ldapasn1.SearchResultEntry, name: str) -> tuple[bytes, ...]:
    for attribute in entry["attributes"]:
        if str(attribute["type"]).lower() == name:
            return tuple(value.asOctets() for value in attribute["vals"])
    return ()


def _required(attributes: Mapping[str, bytes], name: str) -> bytes:
    try:
        return attributes[name]
    except KeyError as error:
        raise LookupError(f"LDAP attribute {name} was not returned") from error


def _text(attributes: Mapping[str, bytes], name: str) -> str:
    return _required(attributes, name).decode("utf-8")


def _domain_from_dn(distinguished_name: str) -> str:
    return ".".join(component[3:] for component in distinguished_name.split(",") if component.upper().startswith("DC="))


def _escape_filter(value: str) -> str:
    escaped = value.replace("\\", "\\5c").replace("*", "\\2a")
    return escaped.replace("(", "\\28").replace(")", "\\29").replace("\0", "\\00")
