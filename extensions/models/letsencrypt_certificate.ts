import { z } from "npm:zod@4";
import forge from "npm:node-forge@1.3.1";
import {
  createHash,
  createPrivateKey,
  createSign,
  generateKeyPairSync,
  X509Certificate,
} from "node:crypto";
import { Buffer } from "node:buffer";

// --- Schemas ---

const GlobalArgsSchema = z.object({
  domain: z.string().describe("Primary domain for the certificate"),
  altNames: z.array(z.string()).default([]).describe(
    "Additional Subject Alternative Names",
  ),
  email: z.string().describe("Contact email for ACME account"),
  staging: z.boolean().default(true).describe(
    "Use Let's Encrypt staging environment",
  ),
});

const AccountSchema = z.object({
  accountUrl: z.string(),
  accountKey: z.string().meta({ sensitive: true }),
});

const CertificateSchema = z.object({
  domain: z.string(),
  certificate: z.string(),
  chain: z.string(),
  privateKey: z.string().meta({ sensitive: true }),
  expiry: z.string(),
  issuedAt: z.string(),
});

// --- Constants ---

const LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";
const LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";

// --- Utility Functions ---

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function base64urlEncode(str) {
  return Buffer.from(str, "utf-8").toString("base64url");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// --- ACME Protocol Functions ---

async function fetchDirectory(directoryUrl) {
  const resp = await fetch(directoryUrl);
  if (!resp.ok) {
    throw new Error(`Failed to fetch ACME directory: ${resp.status}`);
  }
  return await resp.json();
}

async function fetchNonce(newNonceUrl) {
  const resp = await fetch(newNonceUrl, { method: "HEAD" });
  const nonce = resp.headers.get("replay-nonce");
  if (!nonce) throw new Error("No replay-nonce in response");
  return nonce;
}

function getPublicJwk(privateKey) {
  const jwk = privateKey.export({ format: "jwk" });
  return { kty: jwk.kty, n: jwk.n, e: jwk.e };
}

function computeJwkThumbprint(privateKey) {
  const jwk = getPublicJwk(privateKey);
  const input = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  return base64url(createHash("sha256").update(input).digest());
}

function signJws(payload, url, nonce, privateKey, accountUrl) {
  const header = { alg: "RS256", nonce, url };
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

async function acmeRequest(url, payload, privateKey, nonce, accountUrl) {
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

async function acmePostAsGet(url, privateKey, nonce, accountUrl) {
  return acmeRequest(url, "", privateKey, nonce, accountUrl);
}

// --- CSR Generation (using node-forge) ---

function createCsr(domain, altNames, certPrivateKeyPem) {
  const forgeKey = forge.pki.privateKeyFromPem(certPrivateKeyPem);
  const forgePublicKey = forge.pki.setRsaPublicKey(forgeKey.n, forgeKey.e);

  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = forgePublicKey;
  csr.setSubject([{ name: "commonName", value: domain }]);

  const allNames = [domain, ...altNames.filter((n) => n !== domain)];
  csr.setAttributes([{
    name: "extensionRequest",
    extensions: [{
      name: "subjectAltName",
      altNames: allNames.map((name) => ({ type: 2, value: name })),
    }],
  }]);

  csr.sign(forgeKey, forge.md.sha256.create());

  const asn1 = forge.pki.certificationRequestToAsn1(csr);
  const der = forge.asn1.toDer(asn1);
  return Buffer.from(der.getBytes(), "binary");
}

// --- Certificate Helpers ---

function parseCertExpiry(certPem) {
  const x509 = new X509Certificate(certPem);
  return new Date(x509.validTo);
}

function splitCertChain(fullCert) {
  const certs = fullCert.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  ) || [];
  return {
    cert: certs[0] || fullCert,
    chain: certs.slice(1).join("\n"),
  };
}

function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s/g, "");
  return Buffer.from(b64, "base64");
}

// --- DNS Polling ---

async function pollDnsTxt(domain, expectedValue, logger) {
  const recordName = `_acme-challenge.${domain}`;
  const startTime = Date.now();
  const timeoutMs = 600000;
  const intervalMs = 10000;

  while (Date.now() - startTime < timeoutMs) {
    try {
      const records = await Deno.resolveDns(recordName, "TXT");
      if (records.flat().includes(expectedValue)) {
        logger.info("DNS TXT record verified for {domain}", {
          domain: recordName,
        });
        return;
      }
    } catch {
      // Record may not exist yet
    }

    logger.info(
      "Waiting for TXT record at {domain}... ({elapsed}s elapsed)",
      {
        domain: recordName,
        elapsed: Math.round((Date.now() - startTime) / 1000),
      },
    );
    await sleep(intervalMs);
  }

  throw new Error(
    `Timed out waiting for DNS TXT record at ${recordName}`,
  );
}

// --- Certificate Order Flow ---

async function orderCertificate(
  accountKey,
  accountUrl,
  domain,
  altNames,
  directoryUrl,
  logger,
) {
  const directory = await fetchDirectory(directoryUrl);
  let nonce = await fetchNonce(directory.newNonce);

  // Create order
  const allDomains = [domain, ...altNames];
  const identifiers = allDomains.map((d) => ({ type: "dns", value: d }));

  logger.info("Creating ACME order for {domains}", {
    domains: allDomains.join(", "),
  });

  const orderResp = await acmeRequest(
    directory.newOrder,
    { identifiers },
    accountKey,
    nonce,
    accountUrl,
  );
  nonce = orderResp.nonce;
  const order = orderResp.data;
  const orderUrl = orderResp.location;

  // Process authorizations
  const challengeEntries = [];
  for (const authzUrl of order.authorizations) {
    const authzResp = await acmePostAsGet(
      authzUrl,
      accountKey,
      nonce,
      accountUrl,
    );
    nonce = authzResp.nonce;
    const authz = authzResp.data;

    const challenge = authz.challenges.find((c) => c.type === "dns-01");
    if (!challenge) {
      throw new Error(
        `No dns-01 challenge found for ${authz.identifier.value}`,
      );
    }

    const thumbprint = computeJwkThumbprint(accountKey);
    const keyAuth = `${challenge.token}.${thumbprint}`;
    const txtValue = base64url(
      createHash("sha256").update(keyAuth).digest(),
    );

    logger.info(
      'Create TXT record: _acme-challenge.{domain} \u2192 "{value}"',
      { domain: authz.identifier.value, value: txtValue },
    );

    challengeEntries.push({
      domain: authz.identifier.value,
      challenge,
      txtValue,
    });
  }

  // Poll DNS for all challenges
  for (const entry of challengeEntries) {
    await pollDnsTxt(entry.domain, entry.txtValue, logger);
  }

  // Complete challenges
  for (const entry of challengeEntries) {
    logger.info("Completing challenge for {domain}", {
      domain: entry.domain,
    });
    const completeResp = await acmeRequest(
      entry.challenge.url,
      {},
      accountKey,
      nonce,
      accountUrl,
    );
    nonce = completeResp.nonce;

    // Poll for valid status
    let challengeStatus = completeResp.data;
    while (
      challengeStatus.status === "pending" ||
      challengeStatus.status === "processing"
    ) {
      await sleep(2000);
      const pollResp = await acmePostAsGet(
        entry.challenge.url,
        accountKey,
        nonce,
        accountUrl,
      );
      nonce = pollResp.nonce;
      challengeStatus = pollResp.data;
    }

    if (challengeStatus.status !== "valid") {
      throw new Error(
        `Challenge validation failed for ${entry.domain}: ${JSON.stringify(challengeStatus)}`,
      );
    }
  }

  // Generate certificate key and CSR
  logger.info("Generating certificate key and CSR");
  const certKeyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const certPrivateKeyPem = certKeyPair.privateKey.export({
    type: "pkcs8",
    format: "pem",
  });
  const csrDer = createCsr(domain, altNames, certPrivateKeyPem);

  // Finalize order
  logger.info("Finalizing order");
  const finalizeResp = await acmeRequest(
    order.finalize,
    { csr: base64url(csrDer) },
    accountKey,
    nonce,
    accountUrl,
  );
  nonce = finalizeResp.nonce;

  // Poll order until certificate is ready
  let orderStatus = finalizeResp.data;
  while (orderStatus.status === "processing") {
    await sleep(2000);
    const pollResp = await acmePostAsGet(
      orderUrl,
      accountKey,
      nonce,
      accountUrl,
    );
    nonce = pollResp.nonce;
    orderStatus = pollResp.data;
  }

  if (orderStatus.status !== "valid") {
    throw new Error(
      `Order finalization failed: ${JSON.stringify(orderStatus)}`,
    );
  }

  // Download certificate
  logger.info("Downloading certificate");
  const certResp = await acmePostAsGet(
    orderStatus.certificate,
    accountKey,
    nonce,
    accountUrl,
  );

  return {
    certificate: certResp.data,
    privateKey: certPrivateKeyPem,
  };
}

// --- Model ---

export const model = {
  type: "@stack72/letsencrypt-certificate",
  version: "2026.03.04.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    "account": {
      description: "ACME account URL and key",
      schema: AccountSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    "certificate": {
      description: "TLS certificate, chain, and private key",
      schema: CertificateSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
  },
  methods: {
    create: {
      description:
        "Register ACME account, request certificate via DNS-01 challenge, store cert + key",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { domain, altNames, email, staging } = context.globalArgs;
        const logger = context.logger;
        const directoryUrl = staging ? LE_STAGING : LE_PRODUCTION;

        // Generate account key
        logger.info("Generating ACME account key");
        const accountKeyPair = generateKeyPairSync("rsa", {
          modulusLength: 2048,
        });
        const accountKey = accountKeyPair.privateKey;
        const accountKeyPem = accountKey.export({
          type: "pkcs8",
          format: "pem",
        });

        // Fetch directory and register account
        const directory = await fetchDirectory(directoryUrl);
        let nonce = await fetchNonce(directory.newNonce);

        logger.info("Registering ACME account for {email}", { email });
        const accountResp = await acmeRequest(
          directory.newAccount,
          {
            termsOfServiceAgreed: true,
            contact: [`mailto:${email}`],
          },
          accountKey,
          nonce,
          null,
        );
        const accountUrl = accountResp.location;

        // Store account
        const accountHandle = await context.writeResource(
          "account",
          "account",
          {
            accountUrl,
            accountKey: accountKeyPem,
          },
        );

        // Order certificate
        const result = await orderCertificate(
          accountKey,
          accountUrl,
          domain,
          altNames || [],
          directoryUrl,
          logger,
        );

        const { cert, chain } = splitCertChain(result.certificate);
        const expiry = parseCertExpiry(cert);

        const certHandle = await context.writeResource(
          "certificate",
          "certificate",
          {
            domain,
            certificate: cert,
            chain,
            privateKey: result.privateKey,
            expiry: expiry.toISOString(),
            issuedAt: new Date().toISOString(),
          },
        );

        logger.info("Certificate issued for {domain}, expires {expiry}", {
          domain,
          expiry: expiry.toISOString(),
        });

        return { dataHandles: [accountHandle, certHandle] };
      },
    },

    status: {
      description: "Check certificate expiry and renewal status",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const logger = context.logger;

        const content = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "certificate",
        );

        if (!content) {
          throw new Error("No certificate found \u2014 run create first");
        }

        const certData = JSON.parse(new TextDecoder().decode(content));
        const expiry = new Date(certData.expiry);
        const now = new Date();
        const daysRemaining = Math.floor(
          (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
        );
        const needsRenewal = daysRemaining < 30;

        logger.info("Certificate for {domain}", { domain: certData.domain });
        logger.info("Expiry: {expiry}", { expiry: certData.expiry });
        logger.info("Days remaining: {days}", { days: daysRemaining });
        logger.info("Needs renewal: {needsRenewal}", { needsRenewal });

        return { dataHandles: [] };
      },
    },

    renew: {
      description: "Renew certificate using existing ACME account",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { domain, altNames, staging } = context.globalArgs;
        const logger = context.logger;
        const directoryUrl = staging ? LE_STAGING : LE_PRODUCTION;

        const accountContent = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "account",
        );

        if (!accountContent) {
          throw new Error("No ACME account found \u2014 run create first");
        }

        const accountData = JSON.parse(
          new TextDecoder().decode(accountContent),
        );
        const accountKey = createPrivateKey(accountData.accountKey);

        const result = await orderCertificate(
          accountKey,
          accountData.accountUrl,
          domain,
          altNames || [],
          directoryUrl,
          logger,
        );

        const { cert, chain } = splitCertChain(result.certificate);
        const expiry = parseCertExpiry(cert);

        const certHandle = await context.writeResource(
          "certificate",
          "certificate",
          {
            domain,
            certificate: cert,
            chain,
            privateKey: result.privateKey,
            expiry: expiry.toISOString(),
            issuedAt: new Date().toISOString(),
          },
        );

        logger.info("Certificate renewed for {domain}, expires {expiry}", {
          domain,
          expiry: expiry.toISOString(),
        });

        return { dataHandles: [certHandle] };
      },
    },

    revoke: {
      description: "Revoke the current certificate",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const { staging } = context.globalArgs;
        const logger = context.logger;
        const directoryUrl = staging ? LE_STAGING : LE_PRODUCTION;

        const accountContent = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "account",
        );

        if (!accountContent) {
          throw new Error("No ACME account found \u2014 run create first");
        }

        const accountData = JSON.parse(
          new TextDecoder().decode(accountContent),
        );
        const accountKey = createPrivateKey(accountData.accountKey);

        const certContent = await context.dataRepository.getContent(
          context.modelType,
          context.modelId,
          "certificate",
        );

        if (!certContent) {
          throw new Error("No certificate found \u2014 nothing to revoke");
        }

        const certData = JSON.parse(new TextDecoder().decode(certContent));

        const directory = await fetchDirectory(directoryUrl);
        let nonce = await fetchNonce(directory.newNonce);

        const certDer = pemToDer(certData.certificate);

        logger.info("Revoking certificate for {domain}", {
          domain: certData.domain,
        });
        await acmeRequest(
          directory.revokeCert,
          { certificate: base64url(certDer) },
          accountKey,
          nonce,
          accountData.accountUrl,
        );

        logger.info("Certificate revoked successfully");

        return { dataHandles: [] };
      },
    },
  },
};
