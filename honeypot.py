from email.headerregistry import Address
# Libs
import argparse
from ssh_honeypot import *

# Parse arguments


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)

    parser.add_argument('-s', '--ssh', action="store_true")
    parser.add_argument('-w', '--http', action="store_true")

args = parser.parse_args()

try:
    if args.ssh:
        print("[-] Running SSH Honeypot...")
        honeypot(args.address, args.port, args.username, args.password)
    elif args.http:
        print("[-] Running HTTP Honeypot")
        pass
    else:
        print("Please select a honeypot to run (SSH --ssh) or (HTTP --http) ")
except:
    print("Exiting honeypot")
