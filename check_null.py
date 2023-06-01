#!/usr/bin/python
import sys
import argparse
from impacket.smbconnection import SMBConnection
from termcolor import colored
from subprocess import Popen, PIPE

# TODO:
# lsaquery
# dsroledominfo
# getusername
# enumprivs

def check_null_session(ip):
    try:
        conn = SMBConnection(ip, ip, timeout=2)
        conn.login('', '')
        conn.logoff()
        return colored(f"{ip} allows null sessions", 'yellow')
    except Exception as e:
        return None

def list_users(ip):
    cmd = ['rpcclient', '-U', '', '-N', ip, '-c', 'enumdomusers']
    p1 = Popen(cmd, stdout=PIPE)
    p2 = Popen(['cut', '-d[', '-f2'], stdin=p1.stdout, stdout=PIPE)
    p3 = Popen(['cut', '-d]', '-f1'], stdin=p2.stdout, stdout=PIPE)
    p4 = Popen(['sort', '-u'], stdin=p3.stdout, stdout=PIPE)
    output = p4.communicate()[0]
    return output.decode()

def main():
    # Create colored text variables
    description = colored("Check Domain Controllers For Null Sessions", "white", attrs=["bold"])
    tool_by = colored("Penetration Testing Tool by Leon Johnson aka", "white", attrs=["bold"])
    handle = colored("@sho_luv", "yellow", attrs=["bold"])

    # Combine colored text variables into banner
    banner = """
   _______ _     _ _______ _______ _     _      __   _ _     _              
   |       |_____| |______ |       |____/       | \  | |     | |      |     
   |_____  |     | |______ |_____  |    \_      |  \_| |_____| |_____ |_____
                                                                          
                 {}
              {} {}
       """.format(description, tool_by, handle)


    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='IP address or path to a file containing IP addresses (one per line)')
    parser.add_argument('-l', '--list', action='store_true', help='List users of the given IP or IPs')
    parser.add_argument('-f', '--file', help='Output file')

    if len(sys.argv)==1:
        print( banner )
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    ips = []
    try:
        with open(args.input, 'r') as f:
            ips = [line.strip() for line in f]
    except FileNotFoundError:
        ips = [args.input]

    results = []
    for ip in ips:
        result = check_null_session(ip)
        if result is not None:
            results.append(result)
            if args.list:
                users = list_users(ip)
                results.append(f"Users for {ip}:\n{users}")

    if args.file:
        with open(args.file, 'w') as f:
            f.write('\n'.join(results))
    else:
        print('\n'.join(results))

if __name__ == '__main__':
    main()

