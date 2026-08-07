//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Avatar file validation utilities
//

const MAX_AVATAR_BYTES = 2 * 1024 * 1024;
const MIN_AVATAR_EDGE = 64;
const MAX_AVATAR_EDGE = 4096;
const MAX_AVATAR_PIXELS = 8_388_608;
const MAX_PREVIEW_EDGE = 1024;

type AllowedAvatarMimeType = "image/jpeg" | "image/png" | "image/webp";

type ImageDimensions = {
  width: number;
  height: number;
  mimeType: AllowedAvatarMimeType;
};

export type SanitizedAvatar = {
  fileName: string;
  previewDataUrl: string;
  width: number;
  height: number;
};

export class AvatarValidationError extends Error {}

function readUint16BigEndian(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function readUint32BigEndian(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function readAscii(bytes: Uint8Array, offset: number, length: number): string {
  return String.fromCharCode(...bytes.slice(offset, offset + length));
}

function parsePngDimensions(bytes: Uint8Array): ImageDimensions | undefined {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 24 || !signature.every((value, index) => bytes[index] === value)) return undefined;
  if (readAscii(bytes, 12, 4) !== "IHDR") throw new AvatarValidationError("PNG 文件结构无效。");

  return {
    width: readUint32BigEndian(bytes, 16),
    height: readUint32BigEndian(bytes, 20),
    mimeType: "image/png",
  };
}

function isJpegStartOfFrame(marker: number): boolean {
  return marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker);
}

function parseJpegDimensions(bytes: Uint8Array): ImageDimensions | undefined {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return undefined;
  let offset = 2;

  while (offset + 4 <= bytes.length) {
    while (offset < bytes.length && bytes[offset] !== 0xff) offset += 1;
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    if (offset >= bytes.length) break;

    const marker = bytes[offset];
    offset += 1;

    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > bytes.length) break;

    const segmentLength = readUint16BigEndian(bytes, offset);
    if (segmentLength < 2 || offset + segmentLength > bytes.length) break;

    if (isJpegStartOfFrame(marker)) {
      if (segmentLength < 7) break;
      return {
        width: readUint16BigEndian(bytes, offset + 5),
        height: readUint16BigEndian(bytes, offset + 3),
        mimeType: "image/jpeg",
      };
    }

    offset += segmentLength;
  }

  throw new AvatarValidationError("JPEG 文件结构无效或不受支持。");
}

function readUint24LittleEndian(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
}

function parseWebpDimensions(bytes: Uint8Array): ImageDimensions | undefined {
  if (bytes.length < 30 || readAscii(bytes, 0, 4) !== "RIFF" || readAscii(bytes, 8, 4) !== "WEBP") return undefined;
  const chunkType = readAscii(bytes, 12, 4);

  if (chunkType === "VP8X") {
    return {
      width: readUint24LittleEndian(bytes, 24) + 1,
      height: readUint24LittleEndian(bytes, 27) + 1,
      mimeType: "image/webp",
    };
  }

  if (chunkType === "VP8L" && bytes[20] === 0x2f) {
    return {
      width: 1 + (((bytes[22] & 0x3f) << 8) | bytes[21]),
      height: 1 + (((bytes[24] & 0x0f) << 10) | (bytes[23] << 2) | (bytes[22] >> 6)),
      mimeType: "image/webp",
    };
  }

  if (chunkType === "VP8 " && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a) {
    return {
      width: (bytes[26] | (bytes[27] << 8)) & 0x3fff,
      height: (bytes[28] | (bytes[29] << 8)) & 0x3fff,
      mimeType: "image/webp",
    };
  }

  throw new AvatarValidationError("WebP 文件结构无效或不受支持。");
}

function inspectImageHeader(bytes: Uint8Array): ImageDimensions {
  const dimensions = parsePngDimensions(bytes) ?? parseJpegDimensions(bytes) ?? parseWebpDimensions(bytes);
  if (!dimensions) throw new AvatarValidationError("文件内容不是受支持的 PNG、JPEG 或 WebP 图片。");
  return dimensions;
}

function validateImageDimensions({ width, height }: ImageDimensions): void {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) {
    throw new AvatarValidationError("图片尺寸无效。");
  }
  if (width < MIN_AVATAR_EDGE || height < MIN_AVATAR_EDGE) {
    throw new AvatarValidationError(`图片宽高均不能小于 ${MIN_AVATAR_EDGE} 像素。`);
  }
  if (width > MAX_AVATAR_EDGE || height > MAX_AVATAR_EDGE || width * height > MAX_AVATAR_PIXELS) {
    throw new AvatarValidationError("图片尺寸过大，宽高不得超过 4096 像素且总像素不得超过 838 万。");
  }
}

export { inspectImageHeader, validateImageDimensions };

export async function sanitizeAvatarFile(file: File): Promise<SanitizedAvatar> {
  const allowedMimeTypes = new Set<AllowedAvatarMimeType>(["image/jpeg", "image/png", "image/webp"]);
  if (!allowedMimeTypes.has(file.type as AllowedAvatarMimeType)) {
    throw new AvatarValidationError("仅支持 PNG、JPEG 或 WebP 图片，不接受 SVG、GIF 等格式。");
  }
  if (file.size <= 0 || file.size > MAX_AVATAR_BYTES) {
    throw new AvatarValidationError("头像文件必须大于 0 且不超过 2 MiB。");
  }
  if (typeof createImageBitmap !== "function") {
    throw new AvatarValidationError("当前浏览器不支持安全的头像处理流程，请更换现代浏览器。");
  }

  const fileBytes = new Uint8Array(await file.arrayBuffer());
  const headerDimensions = inspectImageHeader(fileBytes);
  if (headerDimensions.mimeType !== file.type) {
    throw new AvatarValidationError("文件声明格式与真实内容不一致。");
  }
  validateImageDimensions(headerDimensions);

  let decodedImage: ImageBitmap;
  try {
    decodedImage = await createImageBitmap(file, { imageOrientation: "none" });
  } catch {
    throw new AvatarValidationError("图片无法安全解码，文件可能已损坏。");
  }

  try {
    if (decodedImage.width !== headerDimensions.width || decodedImage.height !== headerDimensions.height) {
      throw new AvatarValidationError("图片解码尺寸与文件头不一致。");
    }

    const scale = Math.min(1, MAX_PREVIEW_EDGE / decodedImage.width, MAX_PREVIEW_EDGE / decodedImage.height);
    const outputWidth = Math.max(1, Math.round(decodedImage.width * scale));
    const outputHeight = Math.max(1, Math.round(decodedImage.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = outputWidth;
    canvas.height = outputHeight;
    const context = canvas.getContext("2d");
    if (!context) throw new AvatarValidationError("浏览器无法创建安全的头像预览。");

    context.imageSmoothingEnabled = true;
    context.imageSmoothingQuality = "high";
    context.drawImage(decodedImage, 0, 0, outputWidth, outputHeight);
    const previewDataUrl = canvas.toDataURL("image/webp", 0.88);
    if (!previewDataUrl.startsWith("data:image/webp;base64,")) {
      throw new AvatarValidationError("浏览器无法重新编码安全的头像预览。");
    }

    return {
      fileName: "avatar.webp",
      previewDataUrl,
      width: headerDimensions.width,
      height: headerDimensions.height,
    };
  } finally {
    decodedImage.close();
  }
}
