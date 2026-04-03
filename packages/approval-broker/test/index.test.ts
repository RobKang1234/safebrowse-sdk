import { generateKeyPairSync } from "node:crypto";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import { createApprovalBrokerServer } from "../src/index.js";

const activeServers = new Set<import("node:http").Server>();

function testPrivateKeyPem(): string {
  return generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}

async function startBroker(options: { authToken?: string } = {}): Promise<{
  server: import("node:http").Server;
  baseUrl: string;
}> {
  const { server } = await createApprovalBrokerServer({
    privateKeyPem: testPrivateKeyPem(),
    ...options
  });
  activeServers.add(server);
  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(0, "127.0.0.1", () => resolvePromise());
  });
  const address = server.address() as AddressInfo;
  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`
  };
}

afterEach(async () => {
  await Promise.all(
    [...activeServers].map(
      (server) =>
        new Promise<void>((resolvePromise) => {
          server.close(() => resolvePromise());
        })
    )
  );
  activeServers.clear();
  vi.restoreAllMocks();
});

describe("approval broker", () => {
  it("accepts mixed-case bearer headers with repeated whitespace", async () => {
    const { baseUrl } = await startBroker({ authToken: "secret-token-123" });
    const response = await fetch(`${baseUrl}/v5/approval/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "bearer \t  secret-token-123"
      },
      body: JSON.stringify({
        sessionId: "session-1",
        workflowHash: "workflow-1",
        capabilityId: "cap-1",
        capabilityDigest: "digest-1"
      })
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      mode: "external_service"
    });
  });

  it("does not expose internal error messages in broker responses", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { baseUrl } = await startBroker({ authToken: "secret-token-123" });
    const response = await fetch(`${baseUrl}/v5/approval/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer secret-token-123"
      },
      body: "{"
    });

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({
      error: "broker_error"
    });
    expect(errorSpy).toHaveBeenCalled();
  });
});
