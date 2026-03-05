import { Buffer } from "node:buffer";

export function base64url(buf: Uint8Array | Buffer): string {
  return Buffer.from(buf).toString("base64url");
}

export function base64urlEncode(str: string): string {
  return Buffer.from(str, "utf-8").toString("base64url");
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
