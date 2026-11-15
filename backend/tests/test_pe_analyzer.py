import pytest
from app.core.security import validate_pe_magic_bytes, PEValidationError, compute_hashes
from app.services.pe_analyzer import analyze_pe_binary, calculate_shannon_entropy

def test_validate_pe_magic_bytes_valid(valid_pe_bytes: bytes):
    assert validate_pe_magic_bytes(valid_pe_bytes) is True

def test_validate_pe_magic_bytes_invalid_dos():
    invalid_data = b"NOT_A_PE_BINARY" + b"\x00" * 100
    with pytest.raises(PEValidationError, match="Missing Windows DOS header"):
        validate_pe_magic_bytes(invalid_data)

def test_validate_pe_magic_bytes_too_short():
    short_data = b"MZ"
    with pytest.raises(PEValidationError, match="Binary is too small"):
        validate_pe_magic_bytes(short_data)

def test_compute_hashes(valid_pe_bytes: bytes):
    hashes = compute_hashes(valid_pe_bytes)
    assert "sha256" in hashes
    assert "sha1" in hashes
    assert "md5" in hashes
    assert len(hashes["sha256"]) == 64
    assert len(hashes["sha1"]) == 40
    assert len(hashes["md5"]) == 32

def test_analyze_pe_binary(valid_pe_bytes: bytes):
    analysis = analyze_pe_binary(valid_pe_bytes)
    assert analysis.status == "success"
    assert analysis.headers.machine != ""
    assert analysis.headers.number_of_sections >= 1
    assert len(analysis.sections) >= 1
    assert 0.0 <= analysis.file_entropy <= 8.0

def test_calculate_shannon_entropy():
    # Uniform bytes have low entropy
    uniform_zeros = b"\x00" * 1000
    assert calculate_shannon_entropy(uniform_zeros) == 0.0

    # Random-like bytes have higher entropy
    varied_bytes = bytes([i % 256 for i in range(1024)])
    entropy = calculate_shannon_entropy(varied_bytes)
    assert entropy > 7.0

