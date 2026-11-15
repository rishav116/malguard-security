import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
import pefile
from app.models.schemas import (
    PEAnalysisResult,
    PEHeaderInfo,
    PESectionDetail,
)
from app.core.logging import logger

# Well-known suspicious Windows API calls frequently abused in malware workflows
SUSPICIOUS_APIS = {
    "VirtualAlloc": "Dynamic memory allocation (often used for payload unpacking/shellcode)",
    "VirtualProtect": "Altering memory page permissions (e.g. RW to RX for code execution)",
    "WriteProcessMemory": "Cross-process memory writing (Process Injection)",
    "CreateRemoteThread": "Process injection execution",
    "OpenProcess": "Direct target process handle acquisition",
    "SetWindowsHookExA": "System-wide keyboard/mouse hooking (Keylogging)",
    "SetWindowsHookExW": "System-wide keyboard/mouse hooking (Keylogging)",
    "IsDebuggerPresent": "Anti-debugging and sandbox evasion check",
    "CheckRemoteDebuggerPresent": "Anti-debugging inspection",
    "NtQueryInformationProcess": "Low-level anti-analysis inquiry",
    "URLDownloadToFileA": "Out-of-band binary download routine",
    "URLDownloadToFileW": "Out-of-band binary download routine",
    "WinExec": "Legacy command/process execution",
    "ShellExecuteA": "External shell execution",
    "ShellExecuteW": "External shell execution",
}

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates mathematical Shannon entropy (0.0 to 8.0) of raw byte buffer."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1
    for count in frequencies:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)

def analyze_pe_binary(data: bytes) -> PEAnalysisResult:
    """
    Parses a Windows PE binary buffer client-safely using pefile.
    Extracts architectural metadata, section characteristics, imports, and exports.
    """
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as e:
        logger.error(f"pefile parsing failed: {e}")
        raise ValueError(f"PE structure parsing error: {str(e)}")

    try:
        # 1. Header Information
        machine_val = pe.FILE_HEADER.Machine
        machine_name = pefile.MACHINE_TYPE.get(machine_val, f"Unknown (0x{machine_val:X})")
        if isinstance(machine_name, int):
            machine_name = f"Machine-0x{machine_name:X}"
        elif isinstance(machine_name, str) and machine_name.startswith("IMAGE_FILE_MACHINE_"):
            machine_name = machine_name.replace("IMAGE_FILE_MACHINE_", "")

        timestamp_val = pe.FILE_HEADER.TimeDateStamp
        compilation_ts = None
        if timestamp_val > 0:
            try:
                compilation_ts = datetime.fromtimestamp(timestamp_val, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                compilation_ts = None

        characteristics = pe.FILE_HEADER.Characteristics
        is_dll = (characteristics & 0x2000) != 0
        is_executable = (characteristics & 0x0002) != 0

        # Subsystem
        subsystem_val = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
        subsystem_name = pefile.SUBSYSTEM_TYPE.get(subsystem_val, f"Subsystem-{subsystem_val}")
        if isinstance(subsystem_name, str) and subsystem_name.startswith("IMAGE_SUBSYSTEM_"):
            subsystem_name = subsystem_name.replace("IMAGE_SUBSYSTEM_", "")

        # Magic
        magic_val = getattr(pe.OPTIONAL_HEADER, "Magic", 0)
        magic_str = "PE32 (32-bit)" if magic_val == 0x10b else "PE32+ (64-bit)" if magic_val == 0x20b else f"Magic-0x{magic_val:X}"

        entry_point = f"0x{getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0):08X}"
        image_base = f"0x{getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0):08X}"

        headers = PEHeaderInfo(
            machine=machine_name,
            machine_hex=f"0x{machine_val:04X}",
            number_of_sections=pe.FILE_HEADER.NumberOfSections,
            time_date_stamp=timestamp_val,
            compilation_timestamp=compilation_ts,
            characteristics_hex=f"0x{characteristics:04X}",
            is_dll=is_dll,
            is_executable_image=is_executable,
            subsystem=subsystem_name,
            magic=magic_str,
            entry_point_rva=entry_point,
            image_base=image_base,
        )

        # 2. Section Details
        sections: List[PESectionDetail] = []
        for s in pe.sections:
            try:
                sec_name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
            except Exception:
                sec_name = "unknown"
            
            sec_data = s.get_data()
            sec_entropy = calculate_shannon_entropy(sec_data)
            
            chars = s.Characteristics
            is_exec = (chars & 0x20000000) != 0
            is_write = (chars & 0x80000000) != 0

            sections.append(
                PESectionDetail(
                    name=sec_name or "empty",
                    virtual_size=s.Misc_VirtualSize,
                    raw_size=s.SizeOfRawData,
                    entropy=sec_entropy,
                    characteristics_hex=f"0x{chars:08X}",
                    is_executable=is_exec,
                    is_writable=is_write,
                )
            )

        # 3. Import Table
        imported_dlls: List[str] = []
        total_imports = 0
        suspicious_hits: List[str] = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
                    imported_dlls.append(dll_name)
                    for imp in entry.imports:
                        total_imports += 1
                        if imp.name:
                            fn_name = imp.name.decode("utf-8", errors="ignore")
                            if fn_name in SUSPICIOUS_APIS:
                                reason = SUSPICIOUS_APIS[fn_name]
                                hit_desc = f"{fn_name} ({dll_name}): {reason}"
                                if hit_desc not in suspicious_hits:
                                    suspicious_hits.append(hit_desc)
                except Exception as e:
                    logger.debug(f"Error parsing import entry: {e}")

        # 4. Export Table (if present)
        exported_funcs: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        exported_funcs.append(exp.name.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass

        # 5. Overall File Entropy
        file_entropy = calculate_shannon_entropy(data)
        if file_entropy > 7.3:
            suspicious_hits.append(f"Abnormally high section entropy ({file_entropy:.2f} / 8.00) indicates packed or encrypted code sections.")

        return PEAnalysisResult(
            status="success",
            headers=headers,
            sections=sections,
            imported_dlls_count=len(imported_dlls),
            imported_dlls=imported_dlls[:20],
            total_imports_count=total_imports,
            exported_functions_count=len(exported_funcs),
            exported_functions=exported_funcs[:20],
            file_entropy=file_entropy,
            suspicious_indicators=suspicious_hits,
        )
    finally:
        pe.close()
