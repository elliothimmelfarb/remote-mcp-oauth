// The whole flow over a real socket, one step at a time, the way a client
// that follows the 2026-07-28 authorization spec walks it.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { after, before, test } from "node:test";
import { createApp, passwordAuthenticator, toNodeListener } from "../src/index.js";
import { MODERN, PASSWORD, modernHeaders, modernRpc } from "./helpers.js";

let server;
let base;

before(async () => {
  server = http.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  const app = createApp({ issuer: base, authenticateUser: passwordAuthenticator(PASSWORD) });
  server.on("request", toNodeListener(app, { issuer: base }));
});

after(() => server.close());

const post = (url, body) => fetch(url, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(body),
  redirect: "manual"
});

const rpc = (message, token) => fetch(`${base}/mcp`, {
  method: "POST",
  headers: modernHeaders(message, token),
  body: JSON.stringify(message)
});

test("discovery, registration, authorize, token, tool call, step-up, refresh, rejection", async () => {
  // 1. An unauthenticated MCP request is challenged.
  const first = await rpc(modernRpc("tools/list"));
  assert.equal(first.status, 401);
  const challenge = first.headers.get("www-authenticate");
  const metadataUrl = /resource_metadata="([^"]+)"/.exec(challenge)[1];
  const challengedScope = /scope="([^"]+)"/.exec(challenge)[1];

  // 2. Protected resource metadata leads to the authorization server.
  const resource = await (await fetch(metadataUrl)).json();
  assert.equal(resource.resource, `${base}/mcp`);
  const issuer = resource.authorization_servers[0];

  // 3. Authorization server metadata, validated as the spec requires.
  const meta = await (await fetch(`${issuer}/.well-known/oauth-authorization-server`)).json();
  assert.equal(meta.issuer, issuer);
  assert.ok(meta.code_challenge_methods_supported.includes("S256"));

  // 4. Dynamic client registration.
  const redirectUri = "http://127.0.0.1:53682/callback";
  const registered = await fetch(meta.registration_endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "E2E client",
      application_type: "native",
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none"
    })
  });
  assert.equal(registered.status, 201);
  const client = await registered.json();

  // 5. Authorization request with PKCE, state and resource.
  const verifier = crypto.randomBytes(32).toString("base64url");
  const authorize = async (scope, state) => {
    const url = new URL(meta.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: redirectUri,
      code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      state,
      scope,
      resource: resource.resource
    });
    const page = await fetch(url);
    assert.equal(page.status, 200);
    const html = await page.text();
    const requestId = /name="request_id" value="([^"]+)"/.exec(html)[1];
    const cookie = page.headers.getSetCookie()[0].split(";")[0];

    // 6. The person approves.
    const approved = await fetch(url.origin + url.pathname, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie },
      body: new URLSearchParams({ request_id: requestId, decision: "approve", password: PASSWORD }),
      redirect: "manual"
    });
    assert.equal(approved.status, 303);
    const callback = new URL(approved.headers.get("location"));
    assert.equal(callback.origin + callback.pathname, redirectUri);
    assert.equal(callback.searchParams.get("state"), state);
    // RFC 9207: the client checks iss before redeeming the code.
    assert.equal(callback.searchParams.get("iss"), meta.issuer);
    return callback.searchParams.get("code");
  };
  const code = await authorize(challengedScope, "s1");

  // 7. Token exchange.
  const exchanged = await post(meta.token_endpoint, {
    grant_type: "authorization_code",
    client_id: client.client_id,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    resource: resource.resource
  });
  assert.equal(exchanged.status, 200);
  const tokens = await exchanged.json();
  assert.equal(tokens.token_type, "Bearer");
  assert.equal(tokens.scope, "read");

  // 8. Stateless MCP calls with the token.
  const discover = await (await rpc(modernRpc("server/discover"), tokens.access_token)).json();
  assert.ok(discover.result.supportedVersions.includes(MODERN));
  const listed = await (await rpc(modernRpc("tools/list"), tokens.access_token)).json();
  assert.deepEqual(listed.result.tools.map((t) => t.name), ["remember", "whoami"]);
  const whoami = await (await rpc(modernRpc("tools/call", { name: "whoami", arguments: {} }), tokens.access_token)).json();
  assert.equal(whoami.result.structuredContent.client, client.client_id);

  // 9. A bad token is rejected.
  const bad = await rpc(modernRpc("tools/call", { name: "whoami", arguments: {} }), "bad-token");
  assert.equal(bad.status, 401);
  assert.match(bad.headers.get("www-authenticate"), /invalid_token/);

  // 10. A call beyond the granted scope triggers step-up authorization.
  const write = modernRpc("tools/call", { name: "remember", arguments: { text: "hello" } });
  const denied = await rpc(write, tokens.access_token);
  assert.equal(denied.status, 403);
  const needed = /scope="([^"]+)"/.exec(denied.headers.get("www-authenticate"))[1];
  const stepped = await post(meta.token_endpoint, {
    grant_type: "authorization_code",
    client_id: client.client_id,
    code: await authorize(`read ${needed}`, "s2"),
    redirect_uri: redirectUri,
    code_verifier: verifier,
    resource: resource.resource
  });
  const wider = await stepped.json();
  const saved = await (await rpc(write, wider.access_token)).json();
  assert.deepEqual(saved.result.structuredContent.notes, ["hello"]);

  // 11. Refresh rotates, and the old token stops working.
  const refreshed = await post(meta.token_endpoint, {
    grant_type: "refresh_token",
    client_id: client.client_id,
    refresh_token: wider.refresh_token,
    resource: resource.resource
  });
  assert.equal(refreshed.status, 200);
  const next = await refreshed.json();
  assert.equal((await rpc(modernRpc("tools/list"), wider.access_token)).status, 401);
  assert.equal((await rpc(modernRpc("tools/list"), next.access_token)).status, 200);

  // 12. Revocation ends it.
  await post(meta.revocation_endpoint, { token: next.refresh_token, client_id: client.client_id });
  assert.equal((await rpc(modernRpc("tools/list"), next.access_token)).status, 401);
});

test("the server does not trust the Host header", async () => {
  const response = await new Promise((resolve, reject) => {
    const url = new URL(`${base}/.well-known/oauth-authorization-server`);
    http.get({ host: url.hostname, port: url.port, path: url.pathname, headers: { host: "evil.example" } }, (res) => {
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve(JSON.parse(text)));
    }).on("error", reject);
  });
  assert.equal(response.issuer, base);
});
