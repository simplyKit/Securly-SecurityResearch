#!/usr/bin/env python3
"""
Securly Log & Settings File Decryptor

Reverses the encryption and encoding applied to Securly Classroom files:

UNAUTHORIZED USAGE OR DISTRIBUTION OF THIS TOOL IS STRICTLY PROHIBITED.

(C) simplyKatt 2026

1. Log files (.dat) — TripleDES encrypted, 8-byte block processing, no padding
   Location: C:\ProgramData\Securly\data\\00\ and C:\ProgramData\Securly\data\03\...

2. Settings files (.dat) — AES-256 encrypted + GZip compressed (XML payload)
   Location: C:\ProgramData\Securly\d6i4p.dat, fnwcklv.dat, etc.

3. Activity tracker file — AES-256 encrypted (JSON payload)
   Location: C:\ProgramData\Securly\bTtySVd.dat

Usage:
    python decrypt_logs.py <file_path>                     # Auto-detect file type
    python decrypt_logs.py <file_path> --type log          # Force log decryption
    python decrypt_logs.py <file_path> --type settings     # Force settings decryption
    python decrypt_logs.py <file_path> --type activity     # Force activity decryption
    python decrypt_logs.py <file_path> -o output.txt       # Specify output file

Source Reference:   Common/Logging/LogEncryption.cs, 
                    Common/ClassroomSettings.cs,
                    Common/FileSystem/FileHelper.cs
"""

import argparse
import base64
import gzip
import os
import sys
from pathlib import Path
from typing import Optional

from Crypto.Cipher import DES3, AES


# ---------------------------------------------------------------------------
# TripleDES parameters (from Common/Logging/LogEncryption.cs)
# Used for log files in C:\ProgramData\Securly\data\{00,03}\*.dat
#
# WARNING: These are hardcoded keys extracted from the application binaries.
# This tool is strictly for testing and diagnostic purposes.
# ---------------------------------------------------------------------------
LOG_3DES_KEY_B64 = "Pr57tdezBnVoPpCJvkriJxRD82pN5nOH"
LOG_3DES_IV_B64 = "ljHACE0IKLA="
LOG_BLOCK_SIZE = 8  # TripleDES block size in bytes

# ---------------------------------------------------------------------------
# AES-256 parameters (from Common/ClassroomSettings.cs and
# Common/FileSystem/FileHelper.cs)
# Used for settings files (d6i4p.dat, f0w3a.dat, etc.) and the activity
# tracker file (bTtySVd.dat)
#
# WARNING: These are hardcoded keys extracted from the application binaries.
# This tool is strictly for testing and diagnostic purposes.
# ---------------------------------------------------------------------------
AES_KEY_B64 = "AnXVsKUdQEBQj1V5dbi0wL1Poq1+FZ1NDiU3q7aFRec="
AES_IV_B64 = "j2tLnCxamGJ48kWrLawk3Q=="


def _des3_key() -> bytes:
    return base64.b64decode(LOG_3DES_KEY_B64)


def _des3_iv() -> bytes:
    return base64.b64decode(LOG_3DES_IV_B64)


def _aes_key() -> bytes:
    return base64.b64decode(AES_KEY_B64)


def _aes_iv() -> bytes:
    return base64.b64decode(AES_IV_B64)


# ---------------------------------------------------------------------------
# Log file decryption  (mirrors LogEncryption.DecryptLogFile)
# ---------------------------------------------------------------------------

def decrypt_log_bytes(data: bytes) -> bytes:
    """Decrypt TripleDES-encrypted log data (block-by-block, no padding).

    The C# implementation uses PaddingMode.None and processes data in 8-byte
    blocks using TransformBlock (which does not handle padding or finalization).
    We replicate this by using ECB-like block processing within CBC mode by
    creating a fresh cipher for each block — but since the C# code uses a
    single CBC cipher across all blocks, we mirror that with a single CBC
    cipher instance.
    """
    key = _des3_key()
    iv = _des3_iv()

    # The C# code creates a fresh decryptor each time DecryptLogFile is called
    # and processes all data through TransformBlock in 8-byte chunks.
    # PyCryptodome's DES3 CBC with no padding does the same when we feed
    # it full blocks.
    # TripleDES is required here to match the application's existing encryption.
    # This is intentional for decryption of legacy data, not a new crypto choice.
    cipher = DES3.new(key, DES3.MODE_CBC, iv)  # noqa: S305

    # Process in 8-byte blocks, same as the C# code
    output = bytearray()
    offset = 0
    while offset < len(data):
        block = data[offset:offset + LOG_BLOCK_SIZE]
        if len(block) < LOG_BLOCK_SIZE:
            # Pad the short final block with zeros (matches C# behavior where
            # BinaryReader.Read into a new byte[8] zero-fills unused bytes)
            block = block + b'\x00' * (LOG_BLOCK_SIZE - len(block))
        output.extend(cipher.decrypt(block))
        offset += LOG_BLOCK_SIZE

    return bytes(output)


def decrypt_log_file(input_path: str, output_path: Optional[str] = None) -> str:
    """Decrypt a TripleDES-encrypted .dat log file and write the .log output.

    Parameters
    ----------
    input_path : str
        Path to the encrypted .dat log file.
    output_path : str | None
        Path for the decrypted output. Defaults to replacing .dat with .log.

    Returns
    -------
    str
        Path of the decrypted output file.
    """
    if output_path is None:
        p = Path(input_path)
        output_path = str(p.with_suffix('.log')) if p.suffix == '.dat' else input_path + '.log'

    with open(input_path, 'rb') as f:
        encrypted = f.read()

    decrypted = decrypt_log_bytes(encrypted)

    with open(output_path, 'wb') as f:
        f.write(decrypted)

    return output_path


# ---------------------------------------------------------------------------
# Settings file decryption  (mirrors ClassroomSettings.MutexProtectedDeserialize)
# Pipeline: File -> GZip decompress -> AES decrypt -> XML
# ---------------------------------------------------------------------------

def decrypt_settings_bytes(data: bytes) -> str:
    """Decrypt a GZip+AES-256 encrypted settings file to XML string.

    The C# serialization pipeline is:
        XML -> AES encrypt -> GZip compress -> File
    So decryption is:
        File -> GZip decompress -> AES decrypt -> XML
    """
    # Step 1: GZip decompress
    decompressed = gzip.decompress(data)

    # Step 2: AES-256-CBC decrypt
    key = _aes_key()
    iv = _aes_iv()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(decompressed)

    # Remove PKCS7 padding (AesCryptoServiceProvider uses PKCS7 by default)
    if decrypted:
        pad_len = decrypted[-1]
        if 1 <= pad_len <= AES.block_size and all(b == pad_len for b in decrypted[-pad_len:]):
            decrypted = decrypted[:-pad_len]

    return decrypted.decode('utf-8')


def decrypt_settings_file(input_path: str, output_path: Optional[str] = None) -> str:
    """Decrypt a GZip+AES settings .dat file and write the XML output.

    Parameters
    ----------
    input_path : str
        Path to the encrypted settings file (e.g. d6i4p.dat).
    output_path : str | None
        Path for the decrypted output. Defaults to replacing .dat with .xml.

    Returns
    -------
    str
        Path of the decrypted output file.
    """
    if output_path is None:
        p = Path(input_path)
        output_path = str(p.with_suffix('.xml')) if p.suffix == '.dat' else input_path + '.xml'

    with open(input_path, 'rb') as f:
        encrypted = f.read()

    xml_str = decrypt_settings_bytes(encrypted)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(xml_str)

    return output_path


# ---------------------------------------------------------------------------
# Activity tracker file decryption  (mirrors FileHelper.ReadFromFile)
# Pipeline: File -> AES decrypt -> JSON
# ---------------------------------------------------------------------------

def decrypt_activity_bytes(data: bytes) -> str:
    """Decrypt an AES-256 encrypted activity tracker file to JSON string.

    Unlike settings files, activity files are AES-encrypted directly (no GZip).
    """
    key = _aes_key()
    iv = _aes_iv()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)

    # Remove PKCS7 padding
    if decrypted:
        pad_len = decrypted[-1]
        if 1 <= pad_len <= AES.block_size and all(b == pad_len for b in decrypted[-pad_len:]):
            decrypted = decrypted[:-pad_len]

    return decrypted.decode('utf-8')


def decrypt_activity_file(input_path: str, output_path: Optional[str] = None) -> str:
    """Decrypt an AES-encrypted activity .dat file and write the JSON output.

    Parameters
    ----------
    input_path : str
        Path to the encrypted activity file (bTtySVd.dat).
    output_path : str | None
        Path for the decrypted output. Defaults to replacing .dat with .json.

    Returns
    -------
    str
        Path of the decrypted output file.
    """
    if output_path is None:
        p = Path(input_path)
        output_path = str(p.with_suffix('.json')) if p.suffix == '.dat' else input_path + '.json'

    with open(input_path, 'rb') as f:
        encrypted = f.read()

    json_str = decrypt_activity_bytes(encrypted)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(json_str)

    return output_path


# ---------------------------------------------------------------------------
# Auto-detection helpers
# ---------------------------------------------------------------------------

# Log file prefixes (from Common/Log.cs LogTypePrefix)
LOG_PREFIXES = ('DC', 'D7', 'NW', 'SRV', 'DS', 'PP', 'DN', 'DV', 'DU', 'MSI', 'Kjs')

# Known settings filenames
SETTINGS_FILES = {'d6i4p.dat', 'fnwcklv.dat', 'dexter.dat', 'f0w3a.dat', 'winset15.dat'}

# Known activity filename
ACTIVITY_FILES = {'bTtySVd.dat'}


def detect_file_type(file_path: str) -> str:
    """Attempt to determine the file type from the filename.

    Returns
    -------
    str
        One of 'log', 'settings', or 'activity'.
    """
    name = Path(file_path).name

    if name in ACTIVITY_FILES:
        return 'activity'

    if name in SETTINGS_FILES:
        return 'settings'

    # Log files are named like DC20260305_141500.dat
    for prefix in LOG_PREFIXES:
        if name.startswith(prefix):
            return 'log'

    # Check if the file is inside a data\00 or data\03 directory
    parts = Path(file_path).parts
    if 'data' in parts:
        return 'log'

    # Default: try GZip header to distinguish settings from logs
    try:
        with open(file_path, 'rb') as f:
            header = f.read(2)
        if header == b'\x1f\x8b':  # GZip magic number
            return 'settings'
    except OSError:
        pass

    return 'log'


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Decrypt Securly Classroom encrypted files (logs, settings, activity data).',
    )
    parser.add_argument('file', help='Path to the encrypted file')
    parser.add_argument(
        '--type', '-t',
        choices=['log', 'settings', 'activity'],
        default=None,
        help='File type (auto-detected if omitted)',
    )
    parser.add_argument('--output', '-o', default=None, help='Output file path')
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f'Error: file not found: {args.file}', file=sys.stderr)
        sys.exit(1)

    file_type = args.type or detect_file_type(args.file)

    print(f'Detected type: {file_type}')
    print(f'Input:  {args.file}')

    if file_type == 'log':
        out = decrypt_log_file(args.file, args.output)
    elif file_type == 'settings':
        out = decrypt_settings_file(args.file, args.output)
    elif file_type == 'activity':
        out = decrypt_activity_file(args.file, args.output)
    else:
        print(f'Error: unknown type: {file_type}', file=sys.stderr)
        sys.exit(1)

    print(f'Output: {out}')
    print('Done.')


if __name__ == '__main__':
    main()
