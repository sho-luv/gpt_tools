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


## Usage

To use any of the tools in this repository, simply clone the repository to your local machine and run the tool's Python script.

For example, to use `androkey`:

1. Clone the `gpt_tools` repository: `git clone https://github.com/sho-luv/gpt_tools.git`
2. Connect rooted Android device.
2. Run the Python script: `python androkey.py`

## License

This repository is licensed under the [MIT License](https://opensource.org/licenses/MIT).
