import argparse
import base64
import hashlib
import socket
import requests
import os
import subprocess
import sys
import platform

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:

    class DummyColor:
        RESET_ALL = ''
        BRIGHT = ''
        RED = ''
        GREEN = ''
        CYAN = ''
    Fore = Style = DummyColor()

def is_root():
    if platform.system() == "Windows":
        return True
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True

def crypto(args):
    if args.encode:
        result = base64.b64encode(args.encode.encode()).decode()
        print(f"{Fore.CYAN}[+] Base64 Encode: {Fore.RESET}{result}")
    elif args.decode:
        try:
            result = base64.b64decode(args.decode).decode()
            print(f"{Fore.CYAN}[+] Base64 Decode: {Fore.RESET}{result}")
        except Exception:
            print(f"{Fore.RED}[-] Invalid Base64 input.")
    elif args.md5:
        result = hashlib.md5(args.md5.encode()).hexdigest()
        print(f"{Fore.CYAN}[+] MD5 Hash: {Fore.RESET}{result}")
    elif args.sha256:
        result = hashlib.sha256(args.sha256.encode()).hexdigest()
        print(f"{Fore.CYAN}[+] SHA-256 Hash: {Fore.RESET}{result}")
    else:
        print(f"{Fore.RED}[-] No crypto option provided.")

def ipgeo(args):
    try:
        res = requests.get(f"http://api.hackertarget.com/geoip/?q={args.ip}", timeout=7)
        print(f"{Fore.CYAN}{res.text}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error fetching IP info: {e}")

def portscan(args):
    ports = {
        21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
        53: 'DOMAIN', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        443: 'HTTPS', 3306: 'MySQL', 8080: 'HTTP-Proxy'
    }
    try:
        for port, name in ports.items():
            sock = socket.socket()
            sock.settimeout(0.5)
            result = sock.connect_ex((args.ip, port))
            status = f"{Fore.GREEN}OPEN{Fore.RESET}" if result == 0 else f"{Fore.RED}CLOSED{Fore.RESET}"
            print(f"[{port}] {name:<12} {status}")
            sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Error scanning ports: {e}")

def nmap_scan(args):
    print(f"{Fore.CYAN}[+] Scanning {args.ip} with Nmap...")
    try:
        os.system(f"nmap -A -Pn --script=vuln -v {args.ip}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error running nmap: {e}")

def main():
    if not is_root():
        print(f"{Fore.YELLOW}[!] Warning: You are not running as root/admin. Some features may not work properly.{Fore.RESET}")

    parser = argparse.ArgumentParser(description="Zeon CLI Toolkit")
    subparsers = parser.add_subparsers(dest="command")

    crypto_parser = subparsers.add_parser("crypto", help="Cryptographic tools")
    crypto_parser.add_argument("--encode", help="Base64 encode")
    crypto_parser.add_argument("--decode", help="Base64 decode")
    crypto_parser.add_argument("--md5", help="MD5 hash")
    crypto_parser.add_argument("--sha256", help="SHA-256 hash")
    crypto_parser.set_defaults(func=crypto)

    geo_parser = subparsers.add_parser("ipgeo", help="IP Geolocation")
    geo_parser.add_argument("--ip", required=True, help="IP address to lookup")
    geo_parser.set_defaults(func=ipgeo)

    port_parser = subparsers.add_parser("portscan", help="Basic port scanner")
    port_parser.add_argument("--ip", required=True, help="Target IP")
    port_parser.set_defaults(func=portscan)

    nmap_parser = subparsers.add_parser("nmap", help="Advanced Nmap scan")
    nmap_parser.add_argument("--ip", required=True, help="Target IP")
    nmap_parser.set_defaults(func=nmap_scan)

    args = parser.parse_args()

    if args.command:
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
