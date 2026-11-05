// The official TypeScript clients against this server, so the flow is proven
// by code this repo did not write: discovery, registration, PKCE and the token
// exchange. The v1 package speaks only the initialize era. The v2 package is
// the release line for 2026-07-28, and in auto mode it goes stateless.
import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { Client as ModernClient, StreamableHTTPClientTransport as ModernTransport, UnauthorizedError as ModernUnauthorized } from "@modelcontextprotocol/client";
import { createApp, passwordAuthenticator, toNodeListener } from "../src/index.js";
import { PASSWORD } from "./helpers.js";

let server;
let base;

before(async () => {
  server = http.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  const app = createApp({ issuer: base, authenticateUser: passwordAuthenticator(PASSWORD) });
  server.on("request", toNodeListener(app, { issuer: base }));
});

after(() => {
  server.closeAllConnections();
  server.close();
});

function provider() {
  let info; let tokens; let verifier; let pending; let discovery;
  return {
    get redirectUrl() { return "http://127.0.0.1:53682/callback"; },
    get clientMetadata() {
      return { client_name: "SDK", redirect_uris: [this.redirectUrl], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" };
    },
    clientInformation: () => info,
    saveClientInformation: (value) => { info = value; },
    tokens: () => tokens,
    saveTokens: (value) => { tokens = value; },
    saveCodeVerifier: (value) => { verifier = value; },
    codeVerifier: () => verifier,
    redirectToAuthorization: async (url) => { pending = url; },
    saveDiscoveryState: (value) => { discovery = value; },
    discoveryState: () => discovery,
    pendingUrl: () => pending
  };
}

// Stands in for the browser and the person.
async function approve(url) {
  const page = await fetch(url);
  assert.equal(page.status, 200);
  const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())[1];
  const cookie = page.headers.getSetCookie()[0].split(";")[0];
  const response = await fetch(`${base}/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    body: new URLSearchParams({ request_id: requestId, decision: "approve", password: PASSWORD }),
    redirect: "manual"
  });
  return new URL(response.headers.get("location")).searchParams;
}

test("the official SDK client completes OAuth and calls a tool", async () => {
  const auth = provider();
  const url = new URL(`${base}/mcp`);
  const client = new Client({ name: "sdk", version: "1.0.0" });
  await assert.rejects(client.connect(new StreamableHTTPClientTransport(url, { authProvider: auth })), UnauthorizedError);

  const pending = auth.pendingUrl();
  assert.ok(pending.searchParams.get("code_challenge"));
  assert.equal(pending.searchParams.get("resource"), url.href);

  const transport = new StreamableHTTPClientTransport(url, { authProvider: auth });
  await transport.finishAuth((await approve(pending)).get("code"));

  const connected = new Client({ name: "sdk", version: "1.0.0" });
  await connected.connect(new StreamableHTTPClientTransport(url, { authProvider: auth }));
  const { tools } = await connected.listTools();
  assert.deepEqual(tools.map((t) => t.name), ["remember", "whoami"]);
  const result = await connected.callTool({ name: "whoami", arguments: {} });
  assert.equal(result.structuredContent.user, "Owner");
  await connected.close();
});

test("the v2 client negotiates 2026-07-28 and calls a tool statelessly", async () => {
  const auth = provider();
  const url = new URL(`${base}/mcp`);
  const options = { versionNegotiation: { mode: "auto" } };
  const first = new ModernClient({ name: "sdk-v2", version: "1.0.0" }, options);
  await assert.rejects(first.connect(new ModernTransport(url, { authProvider: auth })), ModernUnauthorized);

  const pending = auth.pendingUrl();
  assert.equal(pending.searchParams.get("resource"), url.href);
  const transport = new ModernTransport(url, { authProvider: auth });
  await transport.finishAuth(await approve(pending));

  const client = new ModernClient({ name: "sdk-v2", version: "1.0.0" }, options);
  await client.connect(new ModernTransport(url, { authProvider: auth }));
  assert.ok(client.getDiscoverResult()?.supportedVersions.includes("2026-07-28"));
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name), ["remember", "whoami"]);
  const result = await client.callTool({ name: "whoami", arguments: {} });
  assert.equal(result.structuredContent.user, "Owner");
  await client.close();
});
