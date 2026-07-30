from __future__ import annotations

from typing import Annotated

import typer

Target = Annotated[str, typer.Argument(help="domain/username[:password][@target]")]
OptionalTarget = Annotated[str | None, typer.Argument(help="domain/username[:password][@target] for missing inputs.")]
Hashes = Annotated[
    str | None,
    typer.Option("-hashes", "--hashes", help="LMHASH:NTHASH for NTLM authentication; implies -no-pass."),
]
NoPass = Annotated[
    bool,
    typer.Option("-no-pass", "--no-pass", help="Do not prompt when no password or alternate credential is supplied."),
]
Kerberos = Annotated[
    bool,
    typer.Option("-k", "--kerberos", help="Use Kerberos and the current ccache; implies -no-pass."),
]
AesKey = Annotated[
    str | None,
    typer.Option("-aesKey", "--aes-key", help="AES key for Kerberos authentication; implies -no-pass."),
]
DcIp = Annotated[str | None, typer.Option("-dc-ip", "--dc-ip", help="Domain controller IP address.")]
DcHost = Annotated[str | None, typer.Option("-dc-host", "--dc-host", help="Domain controller hostname.")]
