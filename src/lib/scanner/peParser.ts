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
