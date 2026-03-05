import type { KeyObject } from "node:crypto";
import type { Logger } from "jsr:@logtape/logtape@0.8";
import { createHash, generateKeyPairSync } from "node:crypto";
import { base64url, sleep } from "./utils.ts";
import {
  acmePostAsGet,
  acmeRequest,
  computeJwkThumbprint,
  fetchDirectory,
  fetchNonce,
} from "./acme.ts";
import { createCsr } from "./cert.ts";
import { pollDnsTxt } from "./dns.ts";

export async function orderCertificate(
  accountKey: KeyObject,
  accountUrl: string | null,
  domain: string,
  altNames: string[],
  directoryUrl: string,
  logger: Logger,
) {
  const directory = await fetchDirectory(directoryUrl);
  let nonce = await fetchNonce(directory.newNonce);

  // Create order
  const allDomains = [domain, ...altNames];
  const identifiers = allDomains.map((d: string) => ({
    type: "dns",
    value: d,
  }));

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
  nonce = orderResp.nonce!;
  const order = orderResp.data;
  const orderUrl = orderResp.location;

  // Process authorizations
  const challengeEntries: Array<{
    domain: string;
    // deno-lint-ignore no-explicit-any
    challenge: any;
    txtValue: string;
  }> = [];
  for (const authzUrl of order.authorizations) {
    const authzResp = await acmePostAsGet(
      authzUrl,
      accountKey,
      nonce,
      accountUrl,
    );
    nonce = authzResp.nonce!;
    const authz = authzResp.data;

    // deno-lint-ignore no-explicit-any
    const challenge = authz.challenges.find((c: any) => c.type === "dns-01");
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
    nonce = completeResp.nonce!;

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
      nonce = pollResp.nonce!;
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
  }) as string;
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
  nonce = finalizeResp.nonce!;

  // Poll order until certificate is ready
  let orderStatus = finalizeResp.data;
  while (orderStatus.status === "processing") {
    await sleep(2000);
    const pollResp = await acmePostAsGet(
      orderUrl!,
      accountKey,
      nonce,
      accountUrl,
    );
    nonce = pollResp.nonce!;
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
    certificate: certResp.data as string,
    privateKey: certPrivateKeyPem,
  };
}
