import { promises as fs } from "node:fs";
import { createSignal, Severity } from "../core/severity.js";

const SUSPICIOUS_IMPORTS = [
  "VirtualAllocEx",
  "WriteProcessMemory",
  "CreateRemoteThread",
  "NtCreateThreadEx",
  "OpenProcess",
  "ReadProcessMemory",
  "MiniDumpWriteDump",
  "QueueUserAPC",
  "MapViewOfFile",
  "SetWindowsHookEx"
];

const PACKER_MARKERS = ["UPX0", "UPX1", "Themida", "VMProtect", "ASPack"];

export async function analyzePe(filePath, { debug = false } = {}) {
  const buffer = await fs.readFile(filePath);
  if (!isPe(buffer)) {
    return {
      isPe: false,
      signals: [],
      details: null,
      debug: debug
        ? [
            {
              check: "pe.format",
              status: "skipped",
              message: "File is not a Portable Executable.",
              details: {
                mz_header: buffer.length >= 2 ? buffer.toString("ascii", 0, 2) : null,
                bytes_checked: Math.min(buffer.length, 64)
              }
            }
          ]
        : []
    };
  }

  const details = parsePe(buffer);
  const signals = [];
  const trace = debug
    ? [
        {
          check: "pe.format",
          status: "ok",
          message: "Portable Executable headers detected.",
          details: {
            machine: details.machine,
            section_count: details.sections.length,
            has_embedded_signature: details.has_embedded_signature
          }
        }
      ]
    : [];

  const packedSections = details.sections.filter((section) => section.entropy > 7.2 && section.raw_size > 0);
  if (debug) {
    trace.push({
      check: "pe.entropy",
      status: packedSections.length > 0 ? "hit" : "clean",
      message:
        packedSections.length > 0
          ? "One or more sections exceed the entropy threshold."
          : "No PE sections exceed the entropy threshold.",
      details: {
        threshold: 7.2,
        sections: details.sections.map((section) => ({
          name: section.name,
          entropy: Number(section.entropy.toFixed(3)),
          raw_size: section.raw_size
        }))
      }
    });
  }
  if (packedSections.length > 0) {
    signals.push(
      createSignal({
        source: "static.pe",
        category: "high_entropy",
        score: 20,
        severity: Severity.MEDIUM,
        subject: filePath,
        message: "High entropy PE section detected.",
        evidence: {
          sections: packedSections.map((section) => ({
            name: section.name,
            entropy: Number(section.entropy.toFixed(3)),
            raw_size: section.raw_size
          }))
        }
      })
    );
  }

  const suspiciousImports = findAsciiStrings(buffer, SUSPICIOUS_IMPORTS);
  if (debug) {
    trace.push({
      check: "pe.suspicious-imports",
      status: suspiciousImports.length > 0 ? "hit" : "clean",
      message:
        suspiciousImports.length > 0
          ? "Suspicious API imports or strings were found."
          : "No suspicious API imports or strings were found.",
      details: {
        checked_imports: SUSPICIOUS_IMPORTS,
        matched_imports: suspiciousImports
      }
    });
  }
  if (suspiciousImports.length > 0) {
    signals.push(
      createSignal({
        source: "static.pe",
        category: "suspicious_imports",
        score: Math.min(60, 10 + suspiciousImports.length * 10),
        severity: suspiciousImports.length >= 4 ? Severity.HIGH : Severity.MEDIUM,
        subject: filePath,
        message: "Suspicious Windows API imports or strings detected.",
        evidence: { imports: suspiciousImports }
      })
    );
  }

  const packerMarkers = findAsciiStrings(buffer, PACKER_MARKERS);
  if (debug) {
    trace.push({
      check: "pe.packer-markers",
      status: packerMarkers.length > 0 ? "hit" : "clean",
      message: packerMarkers.length > 0 ? "Common packer markers were found." : "No common packer markers were found.",
      details: {
        checked_markers: PACKER_MARKERS,
        matched_markers: packerMarkers
      }
    });
  }
  if (packerMarkers.length > 0) {
    signals.push(
      createSignal({
        source: "static.pe",
        category: "packer_marker",
        score: 30,
        severity: Severity.MEDIUM,
        subject: filePath,
        message: "Common packer marker detected.",
        evidence: { markers: packerMarkers }
      })
    );
  }

  return { isPe: true, signals, details, debug: trace };
}

function isPe(buffer) {
  if (buffer.length < 0x40) return false;
  if (buffer.toString("ascii", 0, 2) !== "MZ") return false;
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset <= 0 || peOffset + 4 >= buffer.length) return false;
  return buffer.toString("ascii", peOffset, peOffset + 4) === "PE\u0000\u0000";
}

function parsePe(buffer) {
  const peOffset = buffer.readUInt32LE(0x3c);
  const fileHeaderOffset = peOffset + 4;
  const numberOfSections = buffer.readUInt16LE(fileHeaderOffset + 2);
  const sizeOfOptionalHeader = buffer.readUInt16LE(fileHeaderOffset + 16);
  const optionalHeaderOffset = fileHeaderOffset + 20;
  const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const optionalMagic = buffer.readUInt16LE(optionalHeaderOffset);
  const dataDirectoryOffset = optionalMagic === 0x20b ? optionalHeaderOffset + 112 : optionalHeaderOffset + 96;
  const securityDirectoryOffset = dataDirectoryOffset + 8 * 4;
  const signatureFileOffset = readUInt32Safe(buffer, securityDirectoryOffset);
  const signatureSize = readUInt32Safe(buffer, securityDirectoryOffset + 4);

  const sections = [];
  for (let index = 0; index < numberOfSections; index += 1) {
    const offset = sectionTableOffset + index * 40;
    if (offset + 40 > buffer.length) break;
    const name = buffer.toString("ascii", offset, offset + 8).replace(/\u0000+$/g, "");
    const virtualSize = buffer.readUInt32LE(offset + 8);
    const rawSize = buffer.readUInt32LE(offset + 16);
    const rawPointer = buffer.readUInt32LE(offset + 20);
    const sectionBytes =
      rawPointer > 0 && rawSize > 0 && rawPointer + rawSize <= buffer.length
        ? buffer.subarray(rawPointer, rawPointer + rawSize)
        : Buffer.alloc(0);
    sections.push({
      name,
      virtual_size: virtualSize,
      raw_size: rawSize,
      entropy: entropy(sectionBytes)
    });
  }

  return {
    machine: readUInt16Safe(buffer, fileHeaderOffset),
    sections,
    has_embedded_signature: signatureFileOffset > 0 && signatureSize > 0
  };
}

function readUInt16Safe(buffer, offset) {
  return offset >= 0 && offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : 0;
}

function readUInt32Safe(buffer, offset) {
  return offset >= 0 && offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : 0;
}

function entropy(buffer) {
  if (buffer.length === 0) return 0;
  const frequencies = new Array(256).fill(0);
  for (const byte of buffer) frequencies[byte] += 1;
  let result = 0;
  for (const count of frequencies) {
    if (count === 0) continue;
    const p = count / buffer.length;
    result -= p * Math.log2(p);
  }
  return result;
}

function findAsciiStrings(buffer, needles) {
  const text = buffer.toString("latin1");
  return needles.filter((needle) => text.includes(needle));
}
