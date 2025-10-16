#!/usr/bin/env python3
"""
SteganoEXE+PDF - Steganography Tool for EXE and PDF carriers
Author / License holder: Ahmed Emad Eldeen Abdelmoneam

Features:
- Hide files inside .exe and .pdf (append-based, compatible with most viewers)
- Optional embedded license block with your name (--license, --license-name)
- AES-CBC encryption (pycryptodome), streamed carrier copy
- Hash verification, safe overwrite prompt or --force
- Detect/extract hidden payload and auto-extract embedded license to separate file
- Mixed Arabic/English messages for convenience
"""

import os
import sys
import argparse
import hashlib
import logging
from pathlib import Path

# Crypto imports with nice error message if missing
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except Exception:
    print("[ERROR] Missing dependency: pycryptodome. Please install it with:")
    print("    python -m pip install pycryptodome")
    sys.exit(2)

# Constants
MARKER = b'STEGANOEXE_v1.0:'  # Unique marker to identify hidden data
SIZE_BYTES = 8  # we store hidden size in 8 bytes big-endian
BUFFER_SIZE = 64 * 1024  # 64KB for streaming copies
DEFAULT_LICENSE_NAME = "Ahmed Emad Eldeen Abdelmoneam"  # default license name (from user memory)

class SteganoEXE:
    def __init__(self, logger=None):
        self.marker = MARKER
        self.logger = logger or logging.getLogger(__name__)

    # ---------- Utility helpers ----------
    @staticmethod
    def sha256_file(path):
        """Compute SHA256 of a file streaming to avoid memory spikes."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def sha256_bytes(data_bytes):
        return hashlib.sha256(data_bytes).hexdigest()

    # ---------- Encryption helpers ----------
    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encrypt data using AES-CBC. Returns iv + ciphertext."""
        key = hashlib.sha256(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv + ct_bytes

    def decrypt_data(self, data: bytes, password: str):
        """Decrypt data using AES-CBC. Returns plaintext bytes or None on failure."""
        try:
            if len(data) < 16:
                self.logger.error("Encrypted payload too short to contain IV.")
                return None
            key = hashlib.sha256(password.encode()).digest()
            iv = data[:16]
            ct = data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plain = unpad(cipher.decrypt(ct), AES.block_size)
            return plain
        except (ValueError, KeyError) as e:
            # Usually ValueError: Padding is incorrect -> wrong password or corrupted data
            self.logger.error("Decryption failed: wrong password or corrupted data.")
            self.logger.debug("Decryption exception:", exc_info=True)
            return None

    # ---------- Helper to build payload with optional license ----------
    def build_payload(self, secret_bytes: bytes, license_name: str = None) -> bytes:
        """
        Payload format (before possible encryption):
        - 1 byte: license flag (0x00 = no license, 0x01 = license present)
        If license present:
            - SIZE_BYTES bytes: license length (big-endian)
            - license bytes (utf-8)
        - then: secret_bytes (raw)
        The entire payload is then appended after marker and hidden-size field.
        """
        if license_name:
            license_text = f"License Owner / حامل الرخصة: {license_name}\n".encode('utf-8')
            self.logger.debug(f"[+] Adding embedded license ({len(license_text)} bytes) for name '{license_name}'")
            payload = b'\x01' + len(license_text).to_bytes(SIZE_BYTES, 'big') + license_text + secret_bytes
        else:
            payload = b'\x00' + secret_bytes
        return payload

    # ---------- Core functionality ----------
    def hide_file(self, carrier_exe: str, file_to_hide: str, output_exe: str, password: str = None,
                  force: bool = False, verify_hash: bool = False, license_name: str = None) -> bool:
        """
        Hide a file inside a carrier (exe or pdf).
        Stream-copy carrier, then append: marker + payload_size(8 bytes) + payload
        Payload may include an embedded license block (see build_payload).
        If password provided, payload is encrypted (iv + ciphertext).
        """
        try:
            carrier = Path(carrier_exe)
            secret = Path(file_to_hide)
            output = Path(output_exe)

            # Basic checks
            if not carrier.is_file():
                self.logger.error(f"Carrier not found: {carrier}")
                return False
            if not secret.is_file():
                self.logger.error(f"File to hide not found: {secret}")
                return False
            if output.exists() and not force:
                # Ask user (interactive). If non-interactive, refuse unless --force provided.
                if sys.stdin.isatty():
                    resp = input(f"[?] Output '{output}' exists. Overwrite? (y/N): ").strip().lower()
                    if resp != 'y':
                        self.logger.info("Aborted by user (will not overwrite).")
                        return False
                else:
                    self.logger.error("Output file exists and --force not provided; cannot overwrite in non-interactive mode.")
                    return False

            # Compute hashes if verify requested
            if verify_hash:
                self.logger.info("[*] Computing original carrier SHA256 (streamed)...")
                orig_hash = self.sha256_file(str(carrier))
                self.logger.info(f"    Original carrier SHA256: {orig_hash}")

            # Stream copy carrier to output to avoid reading whole file in memory
            self.logger.info(f"[+] Copying carrier to output: {carrier} -> {output}")
            with open(str(carrier), 'rb') as src, open(str(output), 'wb') as dst:
                while True:
                    chunk = src.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    dst.write(chunk)

                # Now read secret fully (it's usually small; encryption needs whole content).
                self.logger.info(f"[+] Reading secret file: {secret}")
                with open(str(secret), 'rb') as s_f:
                    secret_data = s_f.read()

                # Build payload with optional license
                payload_raw = self.build_payload(secret_data, license_name=license_name)

                # Encrypt if password provided
                if password:
                    self.logger.info("[+] Encrypting hidden payload with provided password...")
                    payload_to_store = self.encrypt_data(payload_raw, password)
                else:
                    payload_to_store = payload_raw

                # Prepare appended payload: marker + size + data
                hidden_size_bytes = len(payload_to_store).to_bytes(SIZE_BYTES, 'big')
                self.logger.debug(f"[+] Hidden payload size: {len(payload_to_store)} bytes (size field {SIZE_BYTES} bytes)")
                self.logger.info("[+] Appending marker + size + hidden data to output")
                dst.write(self.marker)
                dst.write(hidden_size_bytes)
                dst.write(payload_to_store)

            # Reporting and optional verification
            original_size = carrier.stat().st_size
            new_size = output.stat().st_size
            hidden_size = len(payload_to_store)

            self.logger.info("\n[✓] Success! File hidden successfully.")
            self.logger.info(f"    Original size: {original_size} bytes")
            self.logger.info(f"    Hidden payload (stored): {hidden_size} bytes")
            self.logger.info(f"    Final size: {new_size} bytes")
            self.logger.info(f"    Overhead: {new_size - original_size} bytes")

            if verify_hash:
                self.logger.info("[*] Computing stego file SHA256 (streamed) for verification...")
                stego_hash = self.sha256_file(str(output))
                self.logger.info(f"    Stego file SHA256: {stego_hash}")
                if orig_hash == stego_hash:
                    self.logger.warning("    Note: original and stego hashes are identical (unexpected).")
                else:
                    self.logger.info("    Hashes differ as expected (stego file modified).")

            return True

        except Exception:
            self.logger.exception("[!] Unexpected error in hide_file")
            return False

    def extract_file(self, stego_exe: str, output_file: str, password: str = None) -> bool:
        """
        Extract a hidden file from an executable/pdf.
        If an embedded license is present, writes a separate file named <output_file>.license.txt
        Format handling:
            - read marker, read hidden_size, read payload (maybe encrypted)
            - if decrypted/clear payload starts with 0x01 => license present:
                next SIZE_BYTES is license length, then license bytes, then secret bytes
            - else 0x00 => no license, rest is secret
        """
        try:
            stego = Path(stego_exe)
            outp = Path(output_file)

            if not stego.is_file():
                self.logger.error(f"Stego file not found: {stego}")
                return False

            self.logger.info(f"[+] Reading stego file (streamed header) : {stego}")
            # We'll search for marker efficiently: read tail first (likely appended at end)
            filesize = stego.stat().st_size
            tail_read = min(filesize, 1024 * 1024)  # 1 MB
            with open(str(stego), 'rb') as f:
                if tail_read < filesize:
                    f.seek(filesize - tail_read)
                data_tail = f.read()

            found_at = data_tail.find(self.marker)
            if found_at == -1:
                # fallback full file search
                self.logger.debug("[*] Marker not in tail; scanning full file (may take time)...")
                with open(str(stego), 'rb') as f:
                    data_all = f.read()
                marker_pos = data_all.find(self.marker)
                if marker_pos == -1:
                    self.logger.error("[!] No hidden data marker found in this file.")
                    return False
                # marker found in full data
                size_pos = marker_pos + len(self.marker)
                hidden_size = int.from_bytes(data_all[size_pos:size_pos + SIZE_BYTES], 'big')
                payload_start = size_pos + SIZE_BYTES
                payload = data_all[payload_start:payload_start + hidden_size]
            else:
                # compute true position in file
                if tail_read < filesize:
                    marker_pos = filesize - tail_read + found_at
                else:
                    marker_pos = found_at
                size_pos = marker_pos + len(self.marker)
                with open(str(stego), 'rb') as f:
                    f.seek(size_pos)
                    size_bytes = f.read(SIZE_BYTES)
                    if len(size_bytes) < SIZE_BYTES:
                        self.logger.error("[!] Marker found but size field incomplete/corrupted.")
                        return False
                    hidden_size = int.from_bytes(size_bytes, 'big')
                    payload_start = size_pos + SIZE_BYTES
                    f.seek(payload_start)
                    payload = f.read(hidden_size)

            self.logger.info(f"[+] Hidden payload detected: {hidden_size} bytes (stored)")

            # If password provided, decrypt payload
            if password:
                self.logger.info("[+] Decrypting payload...")
                decrypted = self.decrypt_data(payload, password)
                if decrypted is None:
                    self.logger.error("[!] Decryption failed. Extraction aborted.")
                    return False
                payload = decrypted

            # Parse payload: license flag
            if len(payload) == 0:
                self.logger.error("[!] Payload empty after optional decryption.")
                return False

            flag = payload[0]
            if flag == 1:
                # license present
                if len(payload) < 1 + SIZE_BYTES:
                    self.logger.error("[!] Payload too small to contain license size.")
                    return False
                license_len = int.from_bytes(payload[1:1+SIZE_BYTES], 'big')
                license_start = 1 + SIZE_BYTES
                license_end = license_start + license_len
                if license_end > len(payload):
                    self.logger.error("[!] Payload truncated: license bytes incomplete.")
                    return False
                license_bytes = payload[license_start:license_end]
                secret_bytes = payload[license_end:]
                # write license to file <output>.license.txt
                license_path = outp.with_suffix(outp.suffix + ".license.txt")
                self.logger.info(f"[+] Writing embedded license to: {license_path}")
                with open(str(license_path), 'wb') as lf:
                    lf.write(license_bytes)
                self.logger.info(f"    License ({license_len} bytes) written.")
            elif flag == 0:
                secret_bytes = payload[1:]
            else:
                self.logger.warning("[!] Unknown payload flag; attempting to treat whole payload as secret.")
                secret_bytes = payload

            # Write extracted secret file (prevent accidental overwrite unless user confirms)
            if outp.exists():
                if sys.stdin.isatty():
                    resp = input(f"[?] Output '{outp}' exists. Overwrite? (y/N): ").strip().lower()
                    if resp != 'y':
                        self.logger.info("Aborted by user (will not overwrite).")
                        return False
                else:
                    self.logger.error("Output file exists and interactive prompt not available.")
                    return False

            self.logger.info(f"[+] Writing extracted file to: {outp}")
            with open(str(outp), 'wb') as w:
                w.write(secret_bytes)

            self.logger.info("[✓] File extracted successfully!")
            return True

        except Exception:
            self.logger.exception("[!] Unexpected error in extract_file")
            return False

    def detect_stego(self, filename: str) -> bool:
        """
        Check if file contains hidden data and attempt to report if a license is embedded.
        Attempts efficient tail search first, falls back to full-file.
        """
        try:
            fpath = Path(filename)
            if not fpath.is_file():
                self.logger.error(f"File not found: {fpath}")
                return False

            filesize = fpath.stat().st_size
            tail_read = min(filesize, 1024 * 1024)  # 1 MB
            with open(str(fpath), 'rb') as f:
                if tail_read < filesize:
                    f.seek(filesize - tail_read)
                data = f.read()

            found_at = data.find(self.marker)
            if found_at != -1:
                if tail_read < filesize:
                    marker_pos = filesize - tail_read + found_at
                else:
                    marker_pos = found_at
                size_pos = marker_pos + len(self.marker)
                with open(str(fpath), 'rb') as f:
                    f.seek(size_pos)
                    size_bytes = f.read(SIZE_BYTES)
                    if len(size_bytes) < SIZE_BYTES:
                        self.logger.error("[!] Marker found but size field incomplete/corrupted.")
                        return False
                    hidden_size = int.from_bytes(size_bytes, 'big')
                    # try to read first few bytes of payload to detect license flag
                    f.seek(size_pos + SIZE_BYTES)
                    peek = f.read(1 + SIZE_BYTES)  # flag + license_len
                    license_info = "unknown"
                    if len(peek) >= 1:
                        flag = peek[0]
                        if flag == 1 and len(peek) >= 1 + SIZE_BYTES:
                            license_len = int.from_bytes(peek[1:1+SIZE_BYTES], 'big')
                            license_info = f"embedded license present (len={license_len})"
                        elif flag == 0:
                            license_info = "no embedded license"
                    self.logger.info("[✓] This file contains hidden data!")
                    self.logger.info(f"    Hidden data size: {hidden_size} bytes")
                    self.logger.info(f"    Marker starts at byte: {marker_pos}")
                    self.logger.info(f"    License: {license_info}")
                    return True
            else:
                # fallback full search
                if tail_read < filesize:
                    self.logger.debug("[*] Marker not in tail; scanning full file (may take time)...")
                    with open(str(fpath), 'rb') as f:
                        data_all = f.read()
                    marker_pos_all = data_all.find(self.marker)
                    if marker_pos_all != -1:
                        size_pos = marker_pos_all + len(self.marker)
                        hidden_size = int.from_bytes(data_all[size_pos:size_pos + SIZE_BYTES], 'big')
                        # peek flag
                        peek = data_all[size_pos + SIZE_BYTES:size_pos + SIZE_BYTES + 1 + SIZE_BYTES]
                        license_info = "unknown"
                        if len(peek) >= 1:
                            flag = peek[0]
                            if flag == 1 and len(peek) >= 1 + SIZE_BYTES:
                                license_len = int.from_bytes(peek[1:1+SIZE_BYTES], 'big')
                                license_info = f"embedded license present (len={license_len})"
                            elif flag == 0:
                                license_info = "no embedded license"
                        self.logger.info("[✓] This file contains hidden data!")
                        self.logger.info(f"    Hidden data size: {hidden_size} bytes")
                        self.logger.info(f"    Marker starts at byte: {marker_pos_all}")
                        self.logger.info(f"    License: {license_info}")
                        return True
                self.logger.info("[!] No hidden data detected.")
                return False

        except Exception:
            self.logger.exception("[!] Unexpected error in detect_stego")
            return False


# ---------- CLI ----------
def setup_logger(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: %(message)s",
        datefmt="%H:%M:%S"
    )
    return logging.getLogger("SteganoEXE+PDF")


def main():
    parser = argparse.ArgumentParser(description='SteganoEXE+PDF - Hide files in executables or pdfs (improved)')
    parser.add_argument('action', choices=['hide', 'extract', 'detect'], help='Action to perform')
    parser.add_argument('--carrier', help='Carrier file (exe or pdf) (for hide/detect/extract use)')
    parser.add_argument('--secret', help='File to hide (for hide) or output filename when extracting')
    parser.add_argument('--output', help='Output stego file (for hide) [alternative to --secret in hide]')
    parser.add_argument('--password', help='Password for encryption/decryption (optional)')
    parser.add_argument('--force', action='store_true', help='Overwrite output files without prompt')
    parser.add_argument('--verify-hash', action='store_true', help='Show SHA256 before/after hide (streamed)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output (debug)')
    parser.add_argument('--license', action='store_true', help='Embed a simple license block inside hidden payload (uses --license-name or default)')
    parser.add_argument('--license-name', help='Name to put in embedded license (default is your name)', default=DEFAULT_LICENSE_NAME)
    args = parser.parse_args()

    logger = setup_logger(args.verbose)
    steg = SteganoEXE(logger=logger)

    if args.action == 'hide':
        # accept either --output or --secret as output arg to keep compat
        outpath = args.output if args.output else None
        if not (args.carrier and args.secret and (args.output or args.secret)):
            logger.error("[!] For 'hide' you must provide --carrier, --secret (and --output for the stego file)")
            parser.print_help()
            sys.exit(2)
        # If user used --secret for the file-to-hide but didn't set --output, assume they want output named carrier.stego.ext
        if not args.output:
            carrier = Path(args.carrier)
            outpath = str(carrier.with_name(carrier.stem + "_stego" + carrier.suffix))
            logger.info(f"[*] --output not provided; using default output: {outpath}")
        license_name = args.license_name if args.license else None
        success = steg.hide_file(args.carrier, args.secret, outpath, password=args.password,
                                 force=args.force, verify_hash=args.verify_hash, license_name=license_name)
        sys.exit(0 if success else 1)

    elif args.action == 'extract':
        if not (args.carrier and args.secret):
            logger.error("[!] For 'extract' you must provide --carrier and --secret (as output filename)")
            parser.print_help()
            sys.exit(2)
        success = steg.extract_file(args.carrier, args.secret, password=args.password)
        sys.exit(0 if success else 1)

    elif args.action == 'detect':
        if not args.carrier:
            logger.error("[!] For 'detect' you must provide --carrier")
            parser.print_help()
            sys.exit(2)
        success = steg.detect_stego(args.carrier)
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
