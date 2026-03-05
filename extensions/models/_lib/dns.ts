import type { Logger } from "jsr:@logtape/logtape@0.8";
import { sleep } from "./utils.ts";

export async function pollDnsTxt(
  domain: string,
  expectedValue: string,
  logger: Logger,
): Promise<void> {
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
