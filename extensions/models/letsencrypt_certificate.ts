import { z } from "npm:zod@4";
import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import {
  acmeRequest,
  fetchDirectory,
  fetchNonce,
  LE_PRODUCTION,
  LE_STAGING,
} from "./_lib/acme.ts";
import { parseCertExpiry, pemToDer, splitCertChain } from "./_lib/cert.ts";
import { orderCertificate } from "./_lib/order.ts";
import { base64url } from "./_lib/utils.ts";

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

// --- Model ---

export const model = {
  type: "@stack72/letsencrypt-certificate",
  version: "2026.03.05.1",
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
      // deno-lint-ignore no-explicit-any
      execute: async (_args: any, context: any) => {
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
        const nonce = await fetchNonce(directory.newNonce);

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
      // deno-lint-ignore no-explicit-any
      execute: async (_args: any, context: any) => {
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
      // deno-lint-ignore no-explicit-any
      execute: async (_args: any, context: any) => {
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
      // deno-lint-ignore no-explicit-any
      execute: async (_args: any, context: any) => {
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
        const nonce = await fetchNonce(directory.newNonce);

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
