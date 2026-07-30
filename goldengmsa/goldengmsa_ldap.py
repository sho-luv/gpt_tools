from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from impacket.examples.utils import _get_machine_name, parse_identity
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import LDAP_SID

from goldengmsa_crypto import RootKey, parse_sid

if TYPE_CHECKING:
    from goldengmsa_readers import ReaderSet

_ROOT_KEY_ATTRIBUTES = [
    "cn",
    "msKds-Version",
    "msKds-KDFAlgorithmID",
    "msKds-KDFParam",
    "msKds-SecretAgreementAlgorithmID",
    "msKds-SecretAgreementParam",
    "msKds-PrivateKeyLength",
    "msKds-PublicKeyLength",
    "msKds-DomainID",
    "msKds-CreateTime",
    "msKds-UseStartTime",
    "msKds-RootKeyData",
]


@dataclass(frozen=True, slots=True)
class Credentials:
    domain: str
    username: str
    password: str
    lm_hash: str
    nt_hash: str
    aes_key: str | None
    kerberos: bool
    target_host: str | None

    @classmethod
    def parse(
        cls,
        identity: str,
        hashes: str | None,
        no_pass: bool,
        aes_key: str | None,
        kerberos: bool,
    ) -> Credentials:
        parsed_identity, separator, parsed_host = identity.rpartition("@")
        if not separator:
            parsed_identity = identity
            parsed_host = ""
        if separator and (not parsed_identity or not parsed_host):
            msg = "target must use domain/username[:password]@target"
            raise ValueError(msg)
        if hashes is not None and hashes.count(":") != 1:
            msg = "-hashes must use LMHASH:NTHASH"
            raise ValueError(msg)
        suppress_prompt = no_pass or hashes is not None or aes_key is not None or kerberos
        domain, username, password, lm_hash, nt_hash, use_kerberos = parse_identity(
            parsed_identity,
            hashes,
            suppress_prompt,
            aes_key,
            kerberos,
        )
        if not domain:
            msg = "target must include an authentication domain"
            raise ValueError(msg)
        return cls(domain, username, password, lm_hash, nt_hash, aes_key, use_kerberos, parsed_host or None)


@dataclass(frozen=True, slots=True)
class GmsaRecord:
    name: str
    distinguished_name: str
    sid: str
    password_id: bytes


@dataclass(frozen=True, slots=True)
class RootKeyRecord:
    identifier: uuid.UUID
    root_key: RootKey


class DirectorySession:
    def __init__(self, connection: ldap.LDAPConnection) -> None:
        self._connection = connection

    @classmethod
    def connect(
        cls,
        credentials: Credentials,
        query_domain: str,
        dc_ip: str | None,
        dc_host: str | None,
    ) -> DirectorySession:
        base_dn = ",".join(f"DC={part}" for part in query_domain.split("."))
        if credentials.kerberos:
            target = dc_host or credentials.target_host or _get_machine_name(dc_ip or query_domain, True)
        else:
            target = dc_host or dc_ip or credentials.target_host or query_domain
        connection = ldap.LDAPConnection(f"ldap://{target}", base_dn, dc_ip)
        authenticated = False
        try:
            if credentials.kerberos:
                connection.kerberosLogin(
                    credentials.username,
                    credentials.password,
                    credentials.domain,
                    credentials.lm_hash,
                    credentials.nt_hash,
                    credentials.aes_key or "",
                    kdcHost=dc_ip,
                )
            else:
                connection.login(
                    credentials.username,
                    credentials.password,
                    credentials.domain,
                    credentials.lm_hash,
                    credentials.nt_hash,
                )
            authenticated = True
        finally:
            if not authenticated:
                connection.close()
        return cls(connection)

    def close(self) -> None:
        self._connection.close()

    def find_gmsas(self, sid: str | None = None) -> list[GmsaRecord]:
        search_filter = "(objectCategory=msDS-GroupManagedServiceAccount)"
        if sid is not None:
            sid_value = parse_sid(sid)
            search_filter = f"(&{search_filter}(objectSid={sid_value.formatCanonical()}))"
        entries = self._search(
            search_filter=search_filter,
            attributes=["sAMAccountName", "distinguishedName", "objectSid", "msDS-ManagedPasswordId"],
        )
        return [self._gmsa_record(entry) for entry in entries]

    def find_root_keys(self, identifier: uuid.UUID | None = None) -> list[RootKeyRecord]:
        configuration_dn = self._configuration_naming_context()
        search_filter = "(objectClass=msKds-ProvRootKey)"
        if identifier is not None:
            search_filter = f"(&{search_filter}(cn={identifier}))"
        entries = self._search(
            search_base=configuration_dn,
            search_filter=search_filter,
            attributes=_ROOT_KEY_ATTRIBUTES,
        )
        return [self._root_key_record(entry) for entry in entries]

    def find_reader_sets(
        self,
        sid: str | None = None,
        identifier: uuid.UUID | None = None,
        *,
        expand_groups: bool = True,
    ) -> list[ReaderSet]:
        from goldengmsa_readers import ReaderDiscovery

        return ReaderDiscovery(self._connection).find(sid, identifier, expand_groups)

    def _configuration_naming_context(self) -> str:
        entries = self._search(
            search_base="",
            scope=ldapasn1.Scope("baseObject"),
            search_filter="(objectClass=*)",
            attributes=["configurationNamingContext"],
            paged=False,
        )
        if not entries:
            msg = "RootDSE did not return configurationNamingContext"
            raise LookupError(msg)
        return _text(_attribute_map(entries[0]), "configurationnamingcontext")

    def _search(
        self,
        *,
        search_filter: str,
        attributes: list[str],
        search_base: str | None = None,
        scope: ldapasn1.Scope | None = None,
        paged: bool = True,
    ) -> list[ldapasn1.SearchResultEntry]:
        controls = [ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)] if paged else None
        response = self._connection.search(
            searchBase=search_base,
            scope=scope,
            searchFilter=search_filter,
            attributes=attributes,
            searchControls=controls,
        )
        return [entry for entry in response if isinstance(entry, ldapasn1.SearchResultEntry)]

    @staticmethod
    def _gmsa_record(entry: ldapasn1.SearchResultEntry) -> GmsaRecord:
        attributes = _attribute_map(entry)
        return GmsaRecord(
            name=_text(attributes, "samaccountname"),
            distinguished_name=_text(attributes, "distinguishedname"),
            sid=LDAP_SID(_binary(attributes, "objectsid")).formatCanonical(),
            password_id=_binary(attributes, "msds-managedpasswordid"),
        )

    @staticmethod
    def _root_key_record(entry: ldapasn1.SearchResultEntry) -> RootKeyRecord:
        attributes = _attribute_map(entry)
        identifier = uuid.UUID(_text(attributes, "cn"))
        root_key = RootKey.from_ldap_attributes(
            identifier=identifier.bytes_le,
            version=_integer(attributes, "mskds-version"),
            kdf_algorithm=_text(attributes, "mskds-kdfalgorithmid"),
            kdf_parameters=_binary(attributes, "mskds-kdfparam"),
            secret_algorithm=_text(attributes, "mskds-secretagreementalgorithmid"),
            secret_parameters=_binary(attributes, "mskds-secretagreementparam"),
            private_key_length=_integer(attributes, "mskds-privatekeylength"),
            public_key_length=_integer(attributes, "mskds-publickeylength"),
            domain_id=_text(attributes, "mskds-domainid"),
            create_time=_integer(attributes, "mskds-createtime"),
            use_start_time=_integer(attributes, "mskds-usestarttime"),
            root_key_data=_binary(attributes, "mskds-rootkeydata"),
        )
        return RootKeyRecord(identifier=identifier, root_key=root_key)


def _attribute_map(entry: ldapasn1.SearchResultEntry) -> Mapping[str, bytes]:
    values: dict[str, bytes] = {}
    for attribute in entry["attributes"]:
        name = str(attribute["type"]).lower()
        if attribute["vals"]:
            values[name] = attribute["vals"][0].asOctets()
    return values


def _binary(attributes: Mapping[str, bytes], name: str) -> bytes:
    try:
        return attributes[name]
    except KeyError as error:
        raise LookupError(f"LDAP attribute {name} was not returned") from error


def _text(attributes: Mapping[str, bytes], name: str) -> str:
    return _binary(attributes, name).decode("utf-8")


def _integer(attributes: Mapping[str, bytes], name: str) -> int:
    return int(_text(attributes, name))
