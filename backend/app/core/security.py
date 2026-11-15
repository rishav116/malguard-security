import hashlib
import os
import struct
import tempfile
from contextlib import contextmanager
from typing import Generator, Tuple, Dict
from app.core.logging import logger

class PEValidationError(Exception):
    """Raised when uploaded file fails PE format or magic byte verification."""
    pass

def validate_pe_magic_bytes(data: bytes) -> bool:
    """
    Validates that raw binary data contains valid Windows PE headers:
    1. DOS header signature 'MZ' (0x4D, 0x5A) at offset 0.
    2. e_lfanew pointer at offset 0x3C.
    3. PE signature 'PE\\0\\0' (0x50, 0x45, 0x00, 0x00) at e_lfanew.
    """
    if len(data) < 64:
        raise PEValidationError("Binary is too small to contain a valid Windows DOS header (minimum 64 bytes).")
    
    # Check MZ signature
    if data[:2] != b"MZ":
        raise PEValidationError("Missing Windows DOS header signature ('MZ'). Not a valid Windows executable.")
    
    # Read e_lfanew (4-byte unsigned int, little-endian, at offset 0x3C)
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        raise PEValidationError("Corrupted DOS header: unable to read e_lfanew pointer.")
    
    if e_lfanew + 4 > len(data):
        raise PEValidationError("Invalid PE format: e_lfanew offset points outside binary boundaries.")
    
    # Check PE signature
    pe_sig = data[e_lfanew : e_lfanew + 4]
    if pe_sig != b"PE\x00\x00":
        raise PEValidationError("Missing COFF PE signature ('PE\\0\\0'). File violates PE/COFF specification.")
    
    return True

def compute_hashes(data: bytes) -> Dict[str, str]:
    """Computes SHA-256, SHA-1, and MD5 cryptographic hashes."""
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return {
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5
    }

@contextmanager
def safe_temp_binary(data: bytes) -> Generator[str, None, None]:
    """
    Secure context manager that writes binary bytes to an isolated temporary file,
    yields its absolute path, and guarantees deterministic deletion on exit.
    Uploaded binaries are never executed.
    """
    tmp_file = None
    tmp_path = ""
    try:
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".malguard_tmp", prefix="pe_scan_")
        tmp_path = tmp_file.name
        tmp_file.write(data)
        tmp_file.flush()
        tmp_file.close()
        
        # Enforce non-executable permissions on POSIX systems if applicable
        if hasattr(os, "chmod") and os.name != "nt":
            os.chmod(tmp_path, 0o600)
            
        yield tmp_path
    finally:
        if tmp_file and not tmp_file.closed:
            tmp_file.close()
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {tmp_path}: {e}")

