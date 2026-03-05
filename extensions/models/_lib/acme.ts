import type { KeyObject } from "node:crypto";
import { createHash, createSign } from "node:crypto";
import { base64url, base64urlEncode } from "./utils.ts";

export const LE_STAGING =
  "https://acme-staging-v02.api.letsencrypt.org/directory";
export const LE_PRODUCTION =
  "https://acme-v02.api.letsencrypt.org/directory";

export interface AcmeResponse {
  // deno-lint-ignore no-explicit-any
  data: any;
  status: number;
  nonce: string | null;
  location: string | null;
}

// deno-lint-ignore no-explicit-any
export async function fetchDirectory(directoryUrl: string): Promise<any> {
  const resp = await fetch(directoryUrl);
  if (!resp.ok) {
    throw new Error(`Failed to fetch ACME directory: ${resp.status}`);
  }
  return await resp.json();
}

export async function fetchNonce(newNonceUrl: string): Promise<string> {
  const resp = await fetch(newNonceUrl, { method: "HEAD" });
  const nonce = resp.headers.get("replay-nonce");
  if (!nonce) throw new Error("No replay-nonce in response");
  return nonce;
}

// deno-lint-ignore no-explicit-any
export function getPublicJwk(privateKey: KeyObject): Record<string, any> {
  const jwk = privateKey.export({ format: "jwk" });
  return { kty: jwk.kty, n: jwk.n, e: jwk.e };
}

export function computeJwkThumbprint(privateKey: KeyObject): string {
  const jwk = getPublicJwk(privateKey);
  const input = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  return base64url(createHash("sha256").update(input).digest());
}

function signJws(
  payload: string | Record<string, unknown>,
  url: string,
  nonce: string,
  privateKey: KeyObject,
  accountUrl: string | null,
) {
  // deno-lint-ignore no-explicit-any
  const header: Record<string, any> = { alg: "RS256", nonce, url };
  if (accountUrl) {
    header.kid = accountUrl;
  } else {
    header.jwk = getPublicJwk(privateKey);
  }

  const protectedB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = payload === ""
    ? ""
    : base64urlEncode(JSON.stringify(payload));
  const signingInput = `${protectedB64}.${payloadB64}`;

  const signer = createSign("SHA256");
  signer.update(signingInput);
  const signature = base64url(signer.sign(privateKey));

  return { protected: protectedB64, payload: payloadB64, signature };
}

export async function acmeRequest(
  url: string,
  payload: string | Record<string, unknown>,
  privateKey: KeyObject,
  nonce: string,
  accountUrl: string | null,
): Promise<AcmeResponse> {
  const body = signJws(payload, url, nonce, privateKey, accountUrl);
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/jose+json" },
    body: JSON.stringify(body),
  });

  const newNonce = resp.headers.get("replay-nonce");
  const contentType = resp.headers.get("content-type") || "";
  let data;
  if (contentType.includes("json")) {
    data = await resp.json();
  } else if (resp.status !== 204) {
    data = await resp.text();
  }

  if (resp.status >= 400) {
    throw new Error(
      `ACME error (${resp.status} ${url}): ${JSON.stringify(data)}`,
    );
  }

  return {
    data,
    status: resp.status,
    nonce: newNonce,
    location: resp.headers.get("location"),
  };
}

export async function acmePostAsGet(
  url: string,
  privateKey: KeyObject,
  nonce: string,
  accountUrl: string | null,
): Promise<AcmeResponse> {
  return acmeRequest(url, "", privateKey, nonce, accountUrl);
}
