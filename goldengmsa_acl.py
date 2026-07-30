from __future__ import annotations

import uuid
from typing import Final

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    ACCESS_DENIED_ACE,
    ACCESS_DENIED_OBJECT_ACE,
    ACCESS_MASK,
    ACE,
    SR_SECURITY_DESCRIPTOR,
)

READ_PROPERTY: Final = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP
CONTROL_ACCESS: Final = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
ROOT_KEY_DATA_GUID: Final = uuid.UUID("26627c27-08a2-0a40-a1b1-8dce85b42993")
_ALLOW_ACE_TYPES: Final = {ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE}
_DENY_ACE_TYPES: Final = {ACCESS_DENIED_ACE.ACE_TYPE, ACCESS_DENIED_OBJECT_ACE.ACE_TYPE}


def reader_sids(
    descriptor: bytes,
    *,
    confidential: bool = False,
    object_type: uuid.UUID | None = None,
) -> tuple[str, ...]:
    security_descriptor = SR_SECURITY_DESCRIPTOR(data=descriptor)
    dacl = security_descriptor["Dacl"]
    if dacl == b"":
        return ()
    relevant_aces: list[tuple[str, bool, int]] = []
    for ace in dacl.aces:
        if ace["AceType"] not in _ALLOW_ACE_TYPES | _DENY_ACE_TYPES or ace.hasFlag(ACE.INHERIT_ONLY_ACE):
            continue
        body = ace["Ace"]
        mask = body["Mask"]["Mask"]
        if (
            ace["AceType"]
            in {
                ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
                ACCESS_DENIED_OBJECT_ACE.ACE_TYPE,
            }
            and body["ObjectType"] != b""
            and (object_type is None or uuid.UUID(bytes_le=body["ObjectType"]) != object_type)
        ):
            continue
        rights = mask & (READ_PROPERTY | CONTROL_ACCESS)
        if mask & ACCESS_MASK.GENERIC_ALL:
            rights |= READ_PROPERTY | CONTROL_ACCESS
        elif mask & ACCESS_MASK.GENERIC_READ:
            rights |= READ_PROPERTY
        if rights:
            relevant_aces.append(
                (
                    body["Sid"].formatCanonical(),
                    ace["AceType"] in _ALLOW_ACE_TYPES,
                    rights,
                ),
            )
    required = READ_PROPERTY | CONTROL_ACCESS if confidential else READ_PROPERTY
    readers: list[str] = []
    for sid in dict.fromkeys(item[0] for item in relevant_aces):
        remaining = required
        for ace_sid, allowed, rights in relevant_aces:
            if ace_sid != sid or not rights & remaining:
                continue
            if not allowed:
                break
            remaining &= ~rights
            if not remaining:
                readers.append(sid)
                break
    return tuple(readers)
