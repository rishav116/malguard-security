/**
 * Windows Portable Executable (PE) & SHA-256 Parser
 * Inspects binary buffers client-side according to the Microsoft PE/COFF specification.
 * Extracts genuine PE header attributes, calculates cryptographic SHA-256,
 * and computes byte Shannon entropy.
 */

export interface PESectionInfo {
  name: string;
  virtualSize: number;
  sizeOfRawData: number;
}

export interface PEInspectionResult {
  isValidPE: boolean;
  error?: string;
  fileName: string;
  fileSize: number;
  formattedSize: string;
  sha256: string;
  architecture: string;
  machineHex: string;
  subsystem: string;
  isDLL: boolean;
  targetType: "Executable (.exe)" | "Dynamic Link Library (.dll)" | "Unknown PE";
  numberOfSections: number;
  sections: PESectionInfo[];
  compilationTimestamp?: string;
  optHeaderMagic: "PE32 (32-bit)" | "PE32+ (64-bit)" | "Unknown";
  entropy: number;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

/**
 * Calculates cryptographic SHA-256 hash using the native Web Crypto API.
 * Works seamlessly in both modern browsers and Node/Next.js runtimes.
 */
export async function calculateSHA256(buffer: ArrayBuffer): Promise<string> {
  const subtleCrypto =
    (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) ||
    (typeof window !== "undefined" && window.crypto?.subtle);

  if (!subtleCrypto) {
    throw new Error("Web Crypto API is not available in the current runtime environment.");
  }

  const hashBuffer = await subtleCrypto.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Computes Shannon entropy (0.0 to 8.0) from raw byte distribution.
 * Higher entropy (typically > 7.0) indicates compression, packing, or encryption.
 */
export function calculateShannonEntropy(uint8Array: Uint8Array): number {
  const len = uint8Array.length;
  if (len === 0) return 0;

  const frequencies = new Uint32Array(256);
  for (let i = 0; i < len; i++) {
    frequencies[uint8Array[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }

  return parseFloat(entropy.toFixed(3));
}

/**
 * Inspects a Windows PE file buffer and extracts architectural metadata.
 */
export async function inspectPEBinary(file: File): Promise<PEInspectionResult> {
  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

  // 1. File size validation
  if (file.size > MAX_FILE_SIZE) {
    throw new Error(
      `File exceeds the 10 MB maximum limit (${formatBytes(file.size)}). Please select a PE binary under 10 MB.`
    );
  }

  // 2. Extension validation
  const lowerName = file.name.toLowerCase();
  const isExeExt = lowerName.endsWith(".exe");
  const isDllExt = lowerName.endsWith(".dll");

  if (!isExeExt && !isDllExt) {
    throw new Error(
      "Unsupported file format. MALGUARD AI currently inspects Windows PE binaries (.exe and .dll)."
    );
  }

  // 3. Read array buffer
  const arrayBuffer = await file.arrayBuffer();
  if (arrayBuffer.byteLength < 64) {
    throw new Error("File is too small to contain a valid Windows DOS/PE header.");
  }

  // 4. Calculate SHA-256
  const sha256 = await calculateSHA256(arrayBuffer);

  // 5. Calculate Shannon entropy
  const uint8View = new Uint8Array(arrayBuffer);
  const entropy = calculateShannonEntropy(uint8View);

  // 6. Parse PE Header via DataView
  const view = new DataView(arrayBuffer);

  // Check DOS Header Magic 'MZ' (0x4D, 0x5A)
  const mz0 = view.getUint8(0);
  const mz1 = view.getUint8(1);
  if (mz0 !== 0x4d || mz1 !== 0x5a) {
    throw new Error(
      "Invalid PE format: Missing DOS header signature ('MZ'). This file is not a valid Windows executable."
    );
  }

  // e_lfanew pointer at offset 0x3C
  const peHeaderOffset = view.getUint32(0x3c, true);

  if (peHeaderOffset + 24 > arrayBuffer.byteLength) {
    throw new Error(
      "Invalid PE format: e_lfanew offset points outside the binary boundaries."
    );
  }

  // Check PE Signature 'PE\0\0' (0x50, 0x45, 0x00, 0x00)
  const p0 = view.getUint8(peHeaderOffset);
  const p1 = view.getUint8(peHeaderOffset + 1);
  const p2 = view.getUint8(peHeaderOffset + 2);
  const p3 = view.getUint8(peHeaderOffset + 3);

  if (p0 !== 0x50 || p1 !== 0x45 || p2 !== 0x00 || p3 !== 0x00) {
    throw new Error(
      "Invalid PE format: Missing COFF PE signature ('PE\\0\\0'). The file does not conform to the PE/COFF specification."
    );
  }

  // COFF File Header (20 bytes following 4-byte signature)
  const coffOffset = peHeaderOffset + 4;
  const machine = view.getUint16(coffOffset, true);
  const numberOfSections = view.getUint16(coffOffset + 2, true);
  const timeDateStamp = view.getUint32(coffOffset + 4, true);
  const sizeOfOptionalHeader = view.getUint16(coffOffset + 16, true);
  const characteristics = view.getUint16(coffOffset + 18, true);

  // Architecture mapping
  let architecture = "Unknown Architecture";
  switch (machine) {
    case 0x014c:
      architecture = "Intel 386 or later (x86 32-bit)";
      break;
    case 0x8664:
      architecture = "AMD64 / Intel EM64T (x64 64-bit)";
      break;
    case 0xaa64:
      architecture = "ARM64 Little-Endian";
      break;
    case 0x01c0:
      architecture = "ARM Little-Endian";
      break;
    case 0x0200:
      architecture = "Intel Itanium (IA64)";
      break;
    default:
      architecture = `Custom Architecture (0x${machine.toString(16).toUpperCase()})`;
  }

  // Characteristics & Target Type
  const isDLL = (characteristics & 0x2000) !== 0;
  const isExecutable = (characteristics & 0x0002) !== 0;
  let targetType: "Executable (.exe)" | "Dynamic Link Library (.dll)" | "Unknown PE" =
    "Unknown PE";
  if (isDLL) {
    targetType = "Dynamic Link Library (.dll)";
  } else if (isExecutable) {
    targetType = "Executable (.exe)";
  }

  // Optional Header (if present)
  let optHeaderMagic: "PE32 (32-bit)" | "PE32+ (64-bit)" | "Unknown" = "Unknown";
  let subsystem = "Unknown Subsystem";

  if (sizeOfOptionalHeader >= 2) {
    const optOffset = coffOffset + 20;
    const magic = view.getUint16(optOffset, true);
    if (magic === 0x10b) optHeaderMagic = "PE32 (32-bit)";
    else if (magic === 0x20b) optHeaderMagic = "PE32+ (64-bit)";

    if (sizeOfOptionalHeader >= 70 && optOffset + 70 <= arrayBuffer.byteLength) {
      const subVal = view.getUint16(optOffset + 68, true);
      switch (subVal) {
        case 1:
          subsystem = "Native";
          break;
        case 2:
          subsystem = "Windows GUI (Graphical Interface)";
          break;
        case 3:
          subsystem = "Windows CUI (Console / Command Line)";
          break;
        case 7:
          subsystem = "POSIX CUI";
          break;
        case 9:
          subsystem = "Windows CE GUI";
          break;
        case 10:
          subsystem = "EFI Application";
          break;
        default:
          subsystem = `Subsystem #${subVal}`;
      }
    }
  }

  // Compilation date from TimeDateStamp
  let compilationTimestamp: string | undefined;
  if (timeDateStamp > 0) {
    try {
      compilationTimestamp = new Date(timeDateStamp * 1000).toUTCString();
    } catch {
      compilationTimestamp = undefined;
    }
  }

  // Section Headers
  const sectionsOffset = coffOffset + 20 + sizeOfOptionalHeader;
  const sections: PESectionInfo[] = [];

  for (let i = 0; i < Math.min(numberOfSections, 32); i++) {
    const secStart = sectionsOffset + i * 40;
    if (secStart + 40 <= arrayBuffer.byteLength) {
      let secName = "";
      for (let c = 0; c < 8; c++) {
        const charCode = view.getUint8(secStart + c);
        if (charCode !== 0) secName += String.fromCharCode(charCode);
      }
      const virtualSize = view.getUint32(secStart + 8, true);
      const sizeOfRawData = view.getUint32(secStart + 16, true);
      sections.push({
        name: secName.trim() || `sec_${i}`,
        virtualSize,
        sizeOfRawData,
      });
    }
  }

  return {
    isValidPE: true,
    fileName: file.name,
    fileSize: file.size,
    formattedSize: formatBytes(file.size),
    sha256,
    architecture,
    machineHex: `0x${machine.toString(16).toUpperCase()}`,
    subsystem,
    isDLL,
    targetType,
    numberOfSections,
    sections,
    compilationTimestamp,
    optHeaderMagic,
    entropy,
  };
}

/**
 * Synthesizes a valid, compliant Windows PE32 binary buffer for testing.
 * Contains standard DOS header ('MZ'), e_lfanew pointer, PE signature ('PE\0\0'),
 * COFF file header, Optional header, and .text section.
 */
export function generateTestPE(options?: { name?: string; includeEicar?: boolean }): File {
  const buf = new Uint8Array(512);
  const view = new DataView(buf.buffer);

  // 1. DOS Header: 'MZ' (0x5A4D) at 0x00
  buf[0] = 0x4d; // 'M'
  buf[1] = 0x5a; // 'Z'

  // 2. e_lfanew pointer at 0x3C pointing to offset 0x80 (128)
  const e_lfanew = 0x80;
  view.setUint32(0x3c, e_lfanew, true);

  // 3. PE Signature 'PE\0\0' (0x00004550) at e_lfanew
  buf[e_lfanew] = 0x50; // 'P'
  buf[e_lfanew + 1] = 0x45; // 'E'
  buf[e_lfanew + 2] = 0x00;
  buf[e_lfanew + 3] = 0x00;

  // 4. COFF File Header (20 bytes at e_lfanew + 4)
  const coffOffset = e_lfanew + 4;
  view.setUint16(coffOffset, 0x014c, true); // Machine: x86 Intel 386
  view.setUint16(coffOffset + 2, 1, true); // NumberOfSections: 1
  view.setUint32(coffOffset + 4, 1700000000, true); // TimeDateStamp
  view.setUint32(coffOffset + 8, 0, true); // PointerToSymbolTable
  view.setUint32(coffOffset + 12, 0, true); // NumberOfSymbols
  view.setUint16(coffOffset + 16, 224, true); // SizeOfOptionalHeader
  view.setUint16(coffOffset + 18, 0x0102, true); // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

  // 5. Optional Header (PE32 magic = 0x10b)
  const optOffset = coffOffset + 20;
  view.setUint16(optOffset, 0x010b, true); // Magic: PE32
  view.setUint16(optOffset + 68, 2, true); // Subsystem: Windows GUI

  // 6. Section Header (40 bytes at optOffset + 224)
  const secOffset = optOffset + 224;
  const secName = new TextEncoder().encode(".text\0\0\0");
  buf.set(secName.slice(0, 8), secOffset);
  view.setUint32(secOffset + 8, 0x1000, true); // VirtualSize
  view.setUint32(secOffset + 12, 0x1000, true); // VirtualAddress
  view.setUint32(secOffset + 16, 0x200, true); // SizeOfRawData
  view.setUint32(secOffset + 20, 0x200, true); // PointerToRawData
  view.setUint32(secOffset + 36, 0x60000020, true); // Characteristics: CODE | EXECUTE | READ

  let filename = options?.name || "sample_diagnostic_tool.exe";
  if (options?.includeEicar) {
    // Append standard EICAR test string
    const eicarStr = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const eicarBytes = new TextEncoder().encode(eicarStr);
    const combined = new Uint8Array(buf.length + eicarBytes.length);
    combined.set(buf);
    combined.set(eicarBytes, buf.length);
    filename = options.name || "sample_eicar_test.exe";
    return new File([combined], filename, { type: "application/x-dosexec" });
  }

  return new File([buf], filename, { type: "application/x-dosexec" });
}
