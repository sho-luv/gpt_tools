from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from impacket.dpapi_ng import KDS_SERVICE_LABEL, compute_kdf_context, kdf
from impacket.ldap.ldaptypes import LDAP_SID


@dataclass(frozen=True, slots=True)
class BlobParseError(ValueError):
    blob_name: str
    offset: int

    def __str__(self) -> str:
        return f"{self.blob_name} is truncated or malformed at offset {self.offset}"


@dataclass(frozen=True, slots=True)
class _Cursor:
    data: bytes
    offset: int = 0

    def take(self, size: int, blob_name: str) -> tuple[bytes, _Cursor]:
        end = self.offset + size
        if size < 0 or end > len(self.data):
            raise BlobParseError(blob_name, self.offset)
        return self.data[self.offset : end], _Cursor(self.data, end)

    def uint32(self, blob_name: str) -> tuple[int, _Cursor]:
        raw, cursor = self.take(4, blob_name)
        return struct.unpack("<I", raw)[0], cursor

    def uint64(self, blob_name: str) -> tuple[int, _Cursor]:
        raw, cursor = self.take(8, blob_name)
        return struct.unpack("<Q", raw)[0], cursor


@dataclass(frozen=True, slots=True)
class RootKey:
    identifier: bytes
    hash_name: str
    root_key_data: bytes
    blob: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> RootKey:
        blob_name = "KDS root key blob"
        _, cursor = _Cursor(data).take(4, blob_name)
        identifier, cursor = cursor.take(16, blob_name)
        _, cursor = cursor.take(12, blob_name)

        kdf_algorithm_size, cursor = cursor.uint32(blob_name)
        _, cursor = cursor.take(kdf_algorithm_size, blob_name)
        kdf_parameters_size, cursor = cursor.uint32(blob_name)
        kdf_parameters, cursor = cursor.take(kdf_parameters_size, blob_name)

        _, cursor = cursor.take(4, blob_name)
        secret_algorithm_size, cursor = cursor.uint32(blob_name)
        _, cursor = cursor.take(secret_algorithm_size, blob_name)
        secret_parameters_size, cursor = cursor.uint32(blob_name)
        _, cursor = cursor.take(secret_parameters_size, blob_name)
        _, cursor = cursor.take(36, blob_name)

        domain_id_size, cursor = cursor.uint32(blob_name)
        _, cursor = cursor.take(domain_id_size, blob_name)
        _, cursor = cursor.take(24, blob_name)
        root_key_size, cursor = cursor.uint64(blob_name)
        root_key_data, _ = cursor.take(root_key_size, blob_name)

        parameters = _Cursor(kdf_parameters)
        _, parameters = parameters.take(8, blob_name)
        hash_name_size, parameters = parameters.uint32(blob_name)
        _, parameters = parameters.take(4, blob_name)
        encoded_hash_name, _ = parameters.take(hash_name_size, blob_name)
        try:
            hash_name = encoded_hash_name.decode("utf-16-le").rstrip("\0")
        except UnicodeDecodeError as error:
            raise BlobParseError(blob_name, cursor.offset) from error
        return cls(identifier=identifier, hash_name=hash_name, root_key_data=root_key_data, blob=data)

    @classmethod
    def from_ldap_attributes(
        cls,
        *,
        identifier: bytes,
        version: int,
        kdf_algorithm: str,
        kdf_parameters: bytes,
        secret_algorithm: str,
        secret_parameters: bytes,
        private_key_length: int,
        public_key_length: int,
        domain_id: str,
        create_time: int,
        use_start_time: int,
        root_key_data: bytes,
    ) -> RootKey:
        kdf_algorithm_bytes = kdf_algorithm.encode("utf-16-le")
        secret_algorithm_bytes = secret_algorithm.encode("utf-16-le")
        domain_id_bytes = domain_id.encode("utf-16-le")
        blob = b"".join(
            (
                struct.pack("<I16sIII", version, identifier, 0, version, 0),
                struct.pack("<I", len(kdf_algorithm_bytes)),
                kdf_algorithm_bytes,
                struct.pack("<I", len(kdf_parameters)),
                kdf_parameters,
                struct.pack("<II", 0, len(secret_algorithm_bytes)),
                secret_algorithm_bytes,
                struct.pack("<I", len(secret_parameters)),
                secret_parameters,
                struct.pack("<IIIIIqq", private_key_length, public_key_length, 0, 0, 0, 1, 1),
                struct.pack("<I", len(domain_id_bytes)),
                domain_id_bytes,
                struct.pack("<QQQQ", create_time, use_start_time, 0, len(root_key_data)),
                root_key_data,
            )
        )
        return cls.from_bytes(blob)

    def to_bytes(self) -> bytes:
        return self.blob


@dataclass(frozen=True, slots=True)
class ManagedPasswordId:
    identifier: bytes
    l0_index: int
    l1_index: int
    l2_index: int

    @classmethod
    def from_bytes(cls, data: bytes) -> ManagedPasswordId:
        blob_name = "msDS-ManagedPasswordId blob"
        header, cursor = _Cursor(data).take(52, blob_name)
        _, _, _, l0_index, l1_index, l2_index = struct.unpack_from("<6I", header)
        unknown_size, domain_size, forest_size = struct.unpack_from("<3I", header, 40)
        _, cursor = cursor.take(unknown_size, blob_name)
        _, cursor = cursor.take(domain_size, blob_name)
        _, _ = cursor.take(forest_size, blob_name)
        return cls(
            identifier=header[24:40],
            l0_index=l0_index,
            l1_index=l1_index,
            l2_index=l2_index,
        )


_GMSA_PASSWORD_LABEL: Final = "GMSA PASSWORD\0".encode("utf-16-le")
_GMSA_SECURITY_DESCRIPTOR: Final = bytes.fromhex(
    "010004803000000000000000000000001400000002001c0001000000000014009f011200010100000000000509000000"
    "010100000000000512000000"
)


class KdfResultError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SidRangeError(ValueError):
    label: str
    maximum: int

    def __str__(self) -> str:
        return f"{self.label} must be between 0 and {self.maximum}"


def parse_sid(value: str) -> LDAP_SID:
    parts = value.split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        msg = "SID must use canonical S-revision-authority[-subauthority] form"
        raise ValueError(msg)
    try:
        revision, authority, *subauthorities = (int(part, 10) for part in parts[1:])
    except ValueError as error:
        msg = "SID components must be decimal integers"
        raise ValueError(msg) from error

    _require_range(revision, 0xFF, "SID revision")
    _require_range(authority, 0xFFFFFFFFFFFF, "SID identifier authority")
    if len(subauthorities) > 15:
        msg = "SID cannot contain more than 15 subauthorities"
        raise ValueError(msg)
    for subauthority in subauthorities:
        _require_range(subauthority, 0xFFFFFFFF, "SID subauthority")

    parsed = LDAP_SID()
    parsed.fromCanonical(value)
    return parsed


def _require_range(value: int, maximum: int, label: str) -> None:
    if not 0 <= value <= maximum:
        raise SidRangeError(label, maximum)


def post_process_password_buffer(password: bytes) -> bytes:
    if len(password) < 2 or len(password) % 2 != 0:
        msg = "gMSA password buffer must contain complete UTF-16 code units"
        raise ValueError(msg)
    processed = bytearray(password)
    for offset in range(0, len(processed) - 2, 2):
        if processed[offset : offset + 2] == b"\0\0":
            processed[offset : offset + 2] = b"\x01\0"
    processed[-2:] = b"\0\0"
    return bytes(processed)


def compute_gmsa_password(sid: str, root_key: RootKey, password_id: ManagedPasswordId) -> bytes:
    if root_key.identifier != password_id.identifier:
        msg = "KDS root key does not match msDS-ManagedPasswordId"
        raise ValueError(msg)

    l0_key = kdf(
        root_key.hash_name,
        root_key.root_key_data,
        KDS_SERVICE_LABEL,
        compute_kdf_context(root_key.identifier, password_id.l0_index, -1, -1),
        64,
    )
    l1_key = kdf(
        root_key.hash_name,
        l0_key,
        KDS_SERVICE_LABEL,
        compute_kdf_context(root_key.identifier, password_id.l0_index, 31, -1) + _GMSA_SECURITY_DESCRIPTOR,
        64,
    )
    for l1_index in range(30, password_id.l1_index - 1, -1):
        l1_key = kdf(
            root_key.hash_name,
            l1_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(root_key.identifier, password_id.l0_index, l1_index, -1),
            64,
        )

    l2_key = l1_key
    for l2_index in range(31, password_id.l2_index - 1, -1):
        l2_key = kdf(
            root_key.hash_name,
            l2_key,
            KDS_SERVICE_LABEL,
            compute_kdf_context(
                root_key.identifier,
                password_id.l0_index,
                password_id.l1_index,
                l2_index,
            ),
            64,
        )

    sid_value = parse_sid(sid)
    password = kdf(root_key.hash_name, l2_key, _GMSA_PASSWORD_LABEL, sid_value.getData(), 256)
    if isinstance(password, bytes):
        return password
    raise KdfResultError
