//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the avatar file validation
//

import { describe, it, expect } from "vitest";
import {
  AvatarValidationError,
  inspectImageHeader,
  validateImageDimensions,
} from "./avatar-file";

function createPngBytes(width: number, height: number): Uint8Array {
  const bytes = new Uint8Array(24);
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  signature.forEach((value, index) => { bytes[index] = value; });
  // IHDR marker
  bytes[12] = 0x49; bytes[13] = 0x48; bytes[14] = 0x44; bytes[15] = 0x52;
  // Width (big-endian uint32 at offset 16)
  bytes[16] = (width >>> 24) & 0xff;
  bytes[17] = (width >>> 16) & 0xff;
  bytes[18] = (width >>> 8) & 0xff;
  bytes[19] = width & 0xff;
  // Height (big-endian uint32 at offset 20)
  bytes[20] = (height >>> 24) & 0xff;
  bytes[21] = (height >>> 16) & 0xff;
  bytes[22] = (height >>> 8) & 0xff;
  bytes[23] = height & 0xff;
  return bytes;
}

function createJpegBytes(width: number, height: number): Uint8Array {
  // Minimal JPEG with SOF0 marker
  const bytes = new Uint8Array(30);
  // SOI
  bytes[0] = 0xff; bytes[1] = 0xd8;
  // SOF0 marker at offset 2
  bytes[2] = 0xff; bytes[3] = 0xc0;
  // Segment length (big-endian uint16, includes itself)
  const segmentLength = 17;
  bytes[4] = (segmentLength >>> 8) & 0xff;
  bytes[5] = segmentLength & 0xff;
  // Precision
  bytes[6] = 0x08;
  // Height (big-endian uint16 at offset 7)
  bytes[7] = (height >>> 8) & 0xff;
  bytes[8] = height & 0xff;
  // Width (big-endian uint16 at offset 9)
  bytes[9] = (width >>> 8) & 0xff;
  bytes[10] = width & 0xff;
  return bytes;
}

function createWebpVp8XBytes(width: number, height: number): Uint8Array {
  const bytes = new Uint8Array(30);
  // RIFF
  bytes[0] = 0x52; bytes[1] = 0x49; bytes[2] = 0x46; bytes[3] = 0x46;
  // File size (offset 4-7, can be zero for parsing)
  // WEBP
  bytes[8] = 0x57; bytes[9] = 0x45; bytes[10] = 0x42; bytes[11] = 0x50;
  // VP8X
  bytes[12] = 0x56; bytes[13] = 0x50; bytes[14] = 0x38; bytes[15] = 0x58;
  // Width (24-bit little-endian at offset 24, value = width - 1)
  const w = width - 1;
  bytes[24] = w & 0xff;
  bytes[25] = (w >>> 8) & 0xff;
  bytes[26] = (w >>> 16) & 0xff;
  // Height (24-bit little-endian at offset 27, value = height - 1)
  const h = height - 1;
  bytes[27] = h & 0xff;
  bytes[28] = (h >>> 8) & 0xff;
  bytes[29] = (h >>> 16) & 0xff;
  return bytes;
}

describe("inspectImageHeader (PNG)", () => {
  it("parses valid PNG dimensions", () => {
    const bytes = createPngBytes(256, 256);
    const result = inspectImageHeader(bytes);
    expect(result.mimeType).toBe("image/png");
    expect(result.width).toBe(256);
    expect(result.height).toBe(256);
  });

  it("parses non-square PNG", () => {
    const bytes = createPngBytes(1920, 1080);
    const result = inspectImageHeader(bytes);
    expect(result.width).toBe(1920);
    expect(result.height).toBe(1080);
  });
});

describe("inspectImageHeader (JPEG)", () => {
  it("parses valid JPEG dimensions", () => {
    const bytes = createJpegBytes(512, 512);
    const result = inspectImageHeader(bytes);
    expect(result.mimeType).toBe("image/jpeg");
    expect(result.width).toBe(512);
    expect(result.height).toBe(512);
  });
});

describe("inspectImageHeader (WebP)", () => {
  it("parses valid VP8X WebP dimensions", () => {
    const bytes = createWebpVp8XBytes(800, 600);
    const result = inspectImageHeader(bytes);
    expect(result.mimeType).toBe("image/webp");
    expect(result.width).toBe(800);
    expect(result.height).toBe(600);
  });
});

describe("inspectImageHeader (invalid)", () => {
  it("throws for non-image bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(() => inspectImageHeader(bytes)).toThrow(AvatarValidationError);
  });

  it("throws for too-short PNG", () => {
    const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
    expect(() => inspectImageHeader(bytes)).toThrow(AvatarValidationError);
  });

  it("throws for GIF bytes", () => {
    const bytes = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, ...new Array(18).fill(0)]);
    expect(() => inspectImageHeader(bytes)).toThrow(AvatarValidationError);
  });
});

describe("validateImageDimensions", () => {
  it("accepts 64x64 (minimum edge)", () => {
    expect(() => validateImageDimensions({ width: 64, height: 64, mimeType: "image/png" })).not.toThrow();
  });

  it("accepts 4096x2048 (max edge, within pixel limit)", () => {
    expect(() => validateImageDimensions({ width: 4096, height: 2048, mimeType: "image/png" })).not.toThrow();
  });

  it("rejects 63x63 (below minimum edge)", () => {
    expect(() => validateImageDimensions({ width: 63, height: 63, mimeType: "image/png" })).toThrow(AvatarValidationError);
  });

  it("rejects 4097x4097 (above maximum edge)", () => {
    expect(() => validateImageDimensions({ width: 4097, height: 4097, mimeType: "image/png" })).toThrow(AvatarValidationError);
  });

  it("rejects zero width", () => {
    expect(() => validateImageDimensions({ width: 0, height: 256, mimeType: "image/png" })).toThrow(AvatarValidationError);
  });

  it("rejects negative height", () => {
    expect(() => validateImageDimensions({ width: 256, height: -1, mimeType: "image/png" })).toThrow(AvatarValidationError);
  });

  it("rejects total pixels exceeding limit (4000x4000 = 16M > 8.3M)", () => {
    expect(() => validateImageDimensions({ width: 4000, height: 4000, mimeType: "image/png" })).toThrow(AvatarValidationError);
  });

  it("accepts non-integer values rejection", () => {
    expect(() => validateImageDimensions({ width: 1.5, height: 256, mimeType: "image/png" })).toThrow(AvatarValidationError);
  });
});
