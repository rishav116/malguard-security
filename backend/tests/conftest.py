import os
import struct
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

@pytest.fixture(autouse=True)
def configure_test_environment():
    orig_fallback = settings.ALLOW_IN_MEMORY_FALLBACK
    settings.ALLOW_IN_MEMORY_FALLBACK = True
    yield
    settings.ALLOW_IN_MEMORY_FALLBACK = orig_fallback

def generate_minimal_valid_pe() -> bytes:
    """
    Synthesizes a minimal compliant Windows PE32 binary buffer for testing.
    Contains standard DOS header ('MZ'), e_lfanew pointer, PE signature ('PE\\0\\0'),
    COFF file header, and Optional header.
    """
    buf = bytearray(512)
    
    # 1. DOS Header: 'MZ' at 0x00
    buf[0:2] = b"MZ"
    
    # 2. e_lfanew pointer at 0x3C pointing to offset 0x80 (128)
    e_lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    
    # 3. PE Signature 'PE\0\0' at e_lfanew
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    
    # 4. COFF File Header (20 bytes at e_lfanew + 4)
    coff_offset = e_lfanew + 4
    machine = 0x014C  # x86 Intel 386
    num_sections = 1
    timestamp = 1700000000
    size_of_opt = 224  # Standard PE32 Optional Header size
    characteristics = 0x0102  # Executable image, 32-bit machine
    
    struct.pack_into("<HHIIIHH", buf, coff_offset, machine, num_sections, timestamp, 0, 0, size_of_opt, characteristics)
    
    # 5. Optional Header (PE32 magic = 0x10b)
    opt_offset = coff_offset + 20
    magic = 0x10B  # PE32
    subsystem = 2  # Windows GUI
    struct.pack_into("<H", buf, opt_offset, magic)
    struct.pack_into("<H", buf, opt_offset + 68, subsystem)
    
    # 6. Section Header (40 bytes at opt_offset + size_of_opt)
    sec_offset = opt_offset + size_of_opt
    sec_name = b".text\x00\x00\x00"
    buf[sec_offset : sec_offset + 8] = sec_name
    struct.pack_into("<IIIIII", buf, sec_offset + 8, 0x1000, 0x1000, 0x200, 0x200, 0, 0)
    struct.pack_into("<I", buf, sec_offset + 36, 0x60000020)  # Executable, readable code
    
    return bytes(buf)

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def auth_client() -> TestClient:
    from app.core.auth import get_current_user, UserIdentity
    test_user = UserIdentity(
        user_id="test-analyst-uuid-999",
        email="analyst@malguard.internal",
        role="authenticated",
        is_demo=False
    )
    app.dependency_overrides[get_current_user] = lambda: test_user
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture
def valid_pe_bytes() -> bytes:
    # Use real Windows binary if present on host, else fallback to synthesized PE
    notepad_path = r"C:\Windows\System32\notepad.exe"
    if os.path.exists(notepad_path):
        with open(notepad_path, "rb") as f:
            return f.read()
    return generate_minimal_valid_pe()

@pytest.fixture
def auth_headers() -> dict:
    return {"Authorization": "Bearer mock-test-token"}

