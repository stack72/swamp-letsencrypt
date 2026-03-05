import forge from "npm:node-forge@1.3.1";
import { X509Certificate } from "node:crypto";
import { Buffer } from "node:buffer";

export function createCsr(
  domain: string,
  altNames: string[],
  certPrivateKeyPem: string,
): Buffer {
  const forgeKey = forge.pki.privateKeyFromPem(certPrivateKeyPem);
  const forgePublicKey = forge.pki.setRsaPublicKey(forgeKey.n, forgeKey.e);

  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = forgePublicKey;
  csr.setSubject([{ name: "commonName", value: domain }]);

  const allNames = [domain, ...altNames.filter((n: string) => n !== domain)];
  csr.setAttributes([{
    name: "extensionRequest",
    extensions: [{
      name: "subjectAltName",
      altNames: allNames.map((name: string) => ({ type: 2, value: name })),
    }],
  }]);

  csr.sign(forgeKey, forge.md.sha256.create());

  const asn1 = forge.pki.certificationRequestToAsn1(csr);
  const der = forge.asn1.toDer(asn1);
  return Buffer.from(der.getBytes(), "binary");
}

export function parseCertExpiry(certPem: string): Date {
  const x509 = new X509Certificate(certPem);
  return new Date(x509.validTo);
}

export function splitCertChain(fullCert: string): {
  cert: string;
  chain: string;
} {
  const certs = fullCert.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  ) || [];
  return {
    cert: certs[0] || fullCert,
    chain: certs.slice(1).join("\n"),
  };
}

export function pemToDer(pem: string): Buffer {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s/g, "");
  return Buffer.from(b64, "base64");
}
