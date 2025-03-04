import os
import sys
import argparse

from termcolor import colored
from GUI import RedshiftGUI
from tool import tool_exec


# Funzione per il controllo di ip_forward
def check_ip_forward():
    ip_forward_file = "/proc/sys/net/ipv4/ip_forward"
    with open(ip_forward_file, 'r') as f:
        ip_forward = f.read().strip()
    print(f"Checking {ip_forward_file} value: {ip_forward}")

    if ip_forward == '0':
        print("Switching ip_forwarding to 1 ...")
        os.system(f'echo 1 | sudo tee {ip_forward_file} > /dev/null')
        return True
    return False


# Funzione per ripristinare il valore originale di ip_forward
def restore_ip_forward(modified):
    if modified:
        print("Restoring original ip_forward value ...")
        os.system('echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null')


# Funzione per il parsing degli argomenti
def parse_args():
    parser = argparse.ArgumentParser(description="MITM with ARP spoofing and TCP alteration")
    parser.add_argument("-vip",  "--victim_ip",  required=True, help="Target device IP address")
    parser.add_argument("-sip",  "--server_ip",  required=True, help="Server IP address")
    parser.add_argument("-i",    "--interface",  required=True, help="Network interface")
    parser.add_argument("-p",    "--payload",    help="Payload file (default: '../config/payload.txt')")
    parser.add_argument("-r",    "--rule",       help="Regex rule file (default: '../config//rule.txt')")
    return parser.parse_args()


# Funzione principale
def main():
    print(colored("""\n\n
░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░    
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░    
░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░▒▓██████▓▒░    ░▒▓█▓▒░    
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░    
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░    
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░    
\n\n""", 'red'))

    modified = check_ip_forward()

    try:
        # Se il parametro GUI è passato, avvia la GUI
        if '--gui' in sys.argv:
            print("Running GUI mode...")
            RedshiftGUI()
        else:
            print("Running Bash mode...")

            # Parsing degli argomenti
            args = parse_args()

            # Check per i file di payload e regola
            payload_file = args.payload if args.payload else '../config/payload.txt'
            rule_file = args.rule if args.rule else '../config/rule.txt'

            # Passa i parametri a tool_exec
            tool_exec(args.victim_ip, args.server_ip, args.interface, rule_file, payload_file)
    except:
        pass
    finally:
        restore_ip_forward(modified)
        print("See you soon :)")

if __name__ == '__main__':
    main()
