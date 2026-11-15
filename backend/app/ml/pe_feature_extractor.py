"""
PE Feature Extractor for MALGUARD AI Random Forest Classifier.
Extracts the exact 69 structural and header features defined in the training schema.
Used identically during both training and real-time backend inference.

Feature Category Breakdown (Sum = 69):
  1. DOS Header: 16 features
  2. COFF File Header: 7 features
  3. Optional Header: 28 features
  4. Section Structural Metrics: 9 features
  5. Import Table & Suspicious APIs: 3 features
  6. Export Table & Directory Metadata: 6 features
"""

from typing import Dict, Any, List
import pefile

# Exact canonical feature names and order matching dataset_malwares.csv and model weights
FEATURE_NAMES: List[str] = [
    # 1. DOS Header (16 features)
    "e_cblp",
    "e_cp",
    "e_crlc",
    "e_cparhdr",
    "e_minalloc",
    "e_maxalloc",
    "e_ss",
    "e_sp",
    "e_csum",
    "e_ip",
    "e_cs",
    "e_lfarlc",
    "e_ovno",
    "e_oemid",
    "e_oeminfo",
    "e_lfanew",

    # 2. COFF File Header (7 features)
    "Machine",
    "NumberOfSections",
    "TimeDateStamp",
    "PointerToSymbolTable",
    "NumberOfSymbols",
    "SizeOfOptionalHeader",
    "Characteristics",

    # 3. Optional Header (28 features)
    "Magic",
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "SizeOfCode",
    "SizeOfInitializedData",
    "SizeOfUninitializedData",
    "AddressOfEntryPoint",
    "BaseOfCode",
    "ImageBase",
    "SectionAlignment",
    "FileAlignment",
    "MajorOperatingSystemVersion",
    "MinorOperatingSystemVersion",
    "MajorImageVersion",
    "MinorImageVersion",
    "MajorSubsystemVersion",
    "MinorSubsystemVersion",
    "SizeOfHeaders",
    "CheckSum",
    "SizeOfImage",
    "Subsystem",
    "DllCharacteristics",
    "SizeOfStackReserve",
    "SizeOfStackCommit",
    "SizeOfHeapReserve",
    "SizeOfHeapCommit",
    "LoaderFlags",
    "NumberOfRvaAndSizes",

    # 4. Imports & Suspicious API count (subset)
    "SuspiciousImportFunctions",

    # 5. Section Structural Metrics (9 features)
    "SuspiciousNameSection",
    "SectionsLength",
    "SectionMinEntropy",
    "SectionMinRawsize",
    "SectionMinVirtualsize",
    "SectionMaxPhysical",
    "SectionMaxVirtual",
    "SectionMaxPointerData",
    "SectionMaxChar",

    # 6. Import Table, Export Table & Directory Metadata
    "DirectoryEntryImport",
    "DirectoryEntryImportSize",
    "DirectoryEntryExport",
    "ImageDirectoryEntryExport",
    "ImageDirectoryEntryImport",
    "ImageDirectoryEntryResource",
    "ImageDirectoryEntryException",
    "ImageDirectoryEntrySecurity",
]

# Explicit mutually exclusive category mappings
FEATURE_CATEGORIES: Dict[str, List[str]] = {
    "dos_header": [
        "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc",
        "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno",
        "e_oemid", "e_oeminfo", "e_lfanew"
    ],
    "coff_file_header": [
        "Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable",
        "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics"
    ],
    "optional_header": [
        "Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
        "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
        "BaseOfCode", "ImageBase", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion",
        "MinorSubsystemVersion", "SizeOfHeaders", "CheckSum", "SizeOfImage",
        "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
        "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes"
    ],
    "section_metrics": [
        "SuspiciousNameSection", "SectionsLength", "SectionMinEntropy",
        "SectionMinRawsize", "SectionMinVirtualsize", "SectionMaxPhysical",
        "SectionMaxVirtual", "SectionMaxPointerData", "SectionMaxChar"
    ],
    "import_table_apis": [
        "SuspiciousImportFunctions", "DirectoryEntryImport", "DirectoryEntryImportSize"
    ],
    "export_table_directories": [
        "DirectoryEntryExport", "ImageDirectoryEntryExport", "ImageDirectoryEntryImport",
        "ImageDirectoryEntryResource", "ImageDirectoryEntryException", "ImageDirectoryEntrySecurity"
    ]
}

SUSPICIOUS_IMPORT_FUNCTIONS = {
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "readprocessmemory", "createremotethread",
    "openprocess", "setwindowshookexa", "setwindowshookexw",
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "urldownloadtofilea", "urldownloadtofilew", "winexec", "shellexecutea", "shellexecutew",
    "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
    "getprocaddress", "internetopena", "internetopenw", "internetopenurla", "internetopenurlw",
    "createservicea", "createservicew", "regsetvalueexa", "regsetvalueexw",
    "cryptencrypt", "cryptdecrypt", "connectnamedpipe", "createmutexa", "createmutexw"
}

STANDARD_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".tls", ".debug", ".cors"
}

def extract_features_from_pe(pe: pefile.PE) -> Dict[str, float]:
    """
    Extracts the canonical 69 numerical PE features from an instantiated pefile.PE object.
    Returns an ordered dictionary mapping feature_name -> float value matching FEATURE_NAMES.
    """
    features: Dict[str, float] = {}

    # 1. DOS Header (16 features)
    features["e_cblp"] = float(getattr(pe.DOS_HEADER, "e_cblp", 0))
    features["e_cp"] = float(getattr(pe.DOS_HEADER, "e_cp", 0))
    features["e_crlc"] = float(getattr(pe.DOS_HEADER, "e_crlc", 0))
    features["e_cparhdr"] = float(getattr(pe.DOS_HEADER, "e_cparhdr", 0))
    features["e_minalloc"] = float(getattr(pe.DOS_HEADER, "e_minalloc", 0))
    features["e_maxalloc"] = float(getattr(pe.DOS_HEADER, "e_maxalloc", 0))
    features["e_ss"] = float(getattr(pe.DOS_HEADER, "e_ss", 0))
    features["e_sp"] = float(getattr(pe.DOS_HEADER, "e_sp", 0))
    features["e_csum"] = float(getattr(pe.DOS_HEADER, "e_csum", 0))
    features["e_ip"] = float(getattr(pe.DOS_HEADER, "e_ip", 0))
    features["e_cs"] = float(getattr(pe.DOS_HEADER, "e_cs", 0))
    features["e_lfarlc"] = float(getattr(pe.DOS_HEADER, "e_lfarlc", 0))
    features["e_ovno"] = float(getattr(pe.DOS_HEADER, "e_ovno", 0))
    features["e_oemid"] = float(getattr(pe.DOS_HEADER, "e_oemid", 0))
    features["e_oeminfo"] = float(getattr(pe.DOS_HEADER, "e_oeminfo", 0))
    features["e_lfanew"] = float(getattr(pe.DOS_HEADER, "e_lfanew", 0))

    # 2. COFF File Header (7 features)
    features["Machine"] = float(getattr(pe.FILE_HEADER, "Machine", 0))
    features["NumberOfSections"] = float(getattr(pe.FILE_HEADER, "NumberOfSections", 0))
    features["TimeDateStamp"] = float(getattr(pe.FILE_HEADER, "TimeDateStamp", 0))
    features["PointerToSymbolTable"] = float(getattr(pe.FILE_HEADER, "PointerToSymbolTable", 0))
    features["NumberOfSymbols"] = float(getattr(pe.FILE_HEADER, "NumberOfSymbols", 0))
    features["SizeOfOptionalHeader"] = float(getattr(pe.FILE_HEADER, "SizeOfOptionalHeader", 0))
    features["Characteristics"] = float(getattr(pe.FILE_HEADER, "Characteristics", 0))

    # 3. Optional Header (28 features)
    opt = getattr(pe, "OPTIONAL_HEADER", None)
    if opt:
        features["Magic"] = float(getattr(opt, "Magic", 0))
        features["MajorLinkerVersion"] = float(getattr(opt, "MajorLinkerVersion", 0))
        features["MinorLinkerVersion"] = float(getattr(opt, "MinorLinkerVersion", 0))
        features["SizeOfCode"] = float(getattr(opt, "SizeOfCode", 0))
        features["SizeOfInitializedData"] = float(getattr(opt, "SizeOfInitializedData", 0))
        features["SizeOfUninitializedData"] = float(getattr(opt, "SizeOfUninitializedData", 0))
        features["AddressOfEntryPoint"] = float(getattr(opt, "AddressOfEntryPoint", 0))
        features["BaseOfCode"] = float(getattr(opt, "BaseOfCode", 0))
        features["ImageBase"] = float(getattr(opt, "ImageBase", 0))
        features["SectionAlignment"] = float(getattr(opt, "SectionAlignment", 0))
        features["FileAlignment"] = float(getattr(opt, "FileAlignment", 0))
        features["MajorOperatingSystemVersion"] = float(getattr(opt, "MajorOperatingSystemVersion", 0))
        features["MinorOperatingSystemVersion"] = float(getattr(opt, "MinorOperatingSystemVersion", 0))
        features["MajorImageVersion"] = float(getattr(opt, "MajorImageVersion", 0))
        features["MinorImageVersion"] = float(getattr(opt, "MinorImageVersion", 0))
        features["MajorSubsystemVersion"] = float(getattr(opt, "MajorSubsystemVersion", 0))
        features["MinorSubsystemVersion"] = float(getattr(opt, "MinorSubsystemVersion", 0))
        features["SizeOfHeaders"] = float(getattr(opt, "SizeOfHeaders", 0))
        features["CheckSum"] = float(getattr(opt, "CheckSum", 0))
        features["SizeOfImage"] = float(getattr(opt, "SizeOfImage", 0))
        features["Subsystem"] = float(getattr(opt, "Subsystem", 0))
        features["DllCharacteristics"] = float(getattr(opt, "DllCharacteristics", 0))
        features["SizeOfStackReserve"] = float(getattr(opt, "SizeOfStackReserve", 0))
        features["SizeOfStackCommit"] = float(getattr(opt, "SizeOfStackCommit", 0))
        features["SizeOfHeapReserve"] = float(getattr(opt, "SizeOfHeapReserve", 0))
        features["SizeOfHeapCommit"] = float(getattr(opt, "SizeOfHeapCommit", 0))
        features["LoaderFlags"] = float(getattr(opt, "LoaderFlags", 0))
        features["NumberOfRvaAndSizes"] = float(getattr(opt, "NumberOfRvaAndSizes", 0))
    else:
        for opt_field in [
            "Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
            "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
            "BaseOfCode", "ImageBase", "SectionAlignment", "FileAlignment",
            "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
            "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion",
            "MinorSubsystemVersion", "SizeOfHeaders", "CheckSum", "SizeOfImage",
            "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
            "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes"
        ]:
            features[opt_field] = 0.0

    # 4. Section Analysis (9 features)
    sections = getattr(pe, "sections", [])
    features["SectionsLength"] = float(len(sections))

    if sections:
        entropies = [s.get_entropy() for s in sections]
        raw_sizes = [getattr(s, "SizeOfRawData", 0) for s in sections]
        virt_sizes = [getattr(s, "Misc_VirtualSize", 0) for s in sections]
        phys_addrs = [getattr(s, "Misc_PhysicalAddress", 0) for s in sections]
        virt_addrs = [getattr(s, "VirtualAddress", 0) for s in sections]
        raw_ptrs = [getattr(s, "PointerToRawData", 0) for s in sections]
        chars = [getattr(s, "Characteristics", 0) for s in sections]

        features["SectionMinEntropy"] = float(min(entropies))
        features["SectionMinRawsize"] = float(min(raw_sizes))
        features["SectionMinVirtualsize"] = float(min(virt_sizes))
        features["SectionMaxPhysical"] = float(max(phys_addrs))
        features["SectionMaxVirtual"] = float(max(virt_addrs))
        features["SectionMaxPointerData"] = float(max(raw_ptrs))
        features["SectionMaxChar"] = float(max(chars))

        # Suspicious Section Names
        susp_sec_count = 0
        for s in sections:
            try:
                name = s.Name.decode("utf-8", errors="ignore").strip("\x00").lower()
            except Exception:
                name = ""
            if name and name not in STANDARD_SECTION_NAMES:
                susp_sec_count += 1
        features["SuspiciousNameSection"] = float(susp_sec_count)
    else:
        features["SectionMinEntropy"] = 0.0
        features["SectionMinRawsize"] = 0.0
        features["SectionMinVirtualsize"] = 0.0
        features["SectionMaxPhysical"] = 0.0
        features["SectionMaxVirtual"] = 0.0
        features["SectionMaxPointerData"] = 0.0
        features["SectionMaxChar"] = 0.0
        features["SuspiciousNameSection"] = 0.0

    # 5. Imports and Suspicious API functions
    susp_import_count = 0
    import_dll_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
        import_dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in getattr(entry, "imports", []):
                if imp.name:
                    try:
                        fn = imp.name.decode("utf-8", errors="ignore").lower()
                        if fn in SUSPICIOUS_IMPORT_FUNCTIONS:
                            susp_import_count += 1
                    except Exception:
                        pass

    features["SuspiciousImportFunctions"] = float(susp_import_count)
    features["DirectoryEntryImport"] = float(import_dll_count)

    # 6. Data Directory sizes & addresses
    data_dir = getattr(opt, "DATA_DIRECTORY", []) if opt else []
    
    def get_dir_size(idx: int) -> float:
        if idx < len(data_dir):
            return float(getattr(data_dir[idx], "Size", 0))
        return 0.0

    def get_dir_va(idx: int) -> float:
        if idx < len(data_dir):
            return float(getattr(data_dir[idx], "VirtualAddress", 0))
        return 0.0

    # pefile.DIRECTORY_ENTRY indices:
    # 0: IMAGE_DIRECTORY_ENTRY_EXPORT
    # 1: IMAGE_DIRECTORY_ENTRY_IMPORT
    # 2: IMAGE_DIRECTORY_ENTRY_RESOURCE
    # 3: IMAGE_DIRECTORY_ENTRY_EXCEPTION
    # 4: IMAGE_DIRECTORY_ENTRY_SECURITY
    features["DirectoryEntryImportSize"] = get_dir_size(1)
    features["ImageDirectoryEntryExport"] = get_dir_size(0)
    features["ImageDirectoryEntryImport"] = get_dir_va(1)
    features["ImageDirectoryEntryResource"] = get_dir_size(2)
    features["ImageDirectoryEntryException"] = get_dir_size(3)
    features["ImageDirectoryEntrySecurity"] = get_dir_size(4)

    # 7. Exports
    export_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        export_count = len(getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []))
    features["DirectoryEntryExport"] = float(export_count)

    # Guarantee canonical insertion order matching FEATURE_NAMES exactly
    return {name: features[name] for name in FEATURE_NAMES}

def extract_feature_vector_from_bytes(data: bytes) -> List[float]:
    """
    Parses PE bytes directly and returns the 69-feature vector in canonical order.
    """
    pe = pefile.PE(data=data, fast_load=False)
    try:
        feat_dict = extract_features_from_pe(pe)
        return [feat_dict[name] for name in FEATURE_NAMES]
    finally:
        pe.close()
