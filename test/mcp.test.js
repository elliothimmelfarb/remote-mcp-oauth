import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import { ISSUER, harness, modernHeaders, modernRpc, pkce } from "./helpers.js";

async function signedIn(options, scope = "read write") {
  const h = harness(options);
  const { client } = await h.register();
  const { access_token: token } = await h.tokens(client, { scope });
  return { h, client, token };
}

/* ---------- bearer handling ---------- */

test("no token is a 401 that points at the metadata and names a scope", async () => {
  const h = harness();
  const response = await h.mcp(modernRpc("tools/list"));
  assert.equal(response.status, 401);
  const header = response.headers.get("www-authenticate");
  assert.match(header, /^Bearer /);
  assert.ok(header.includes(`resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/mcp"`));
  assert.match(header, /scope="read"/);
});

test("a bad token is a 401 with invalid_token and no data", async () => {
  const h = harness();
  const response = await h.mcp(modernRpc("tools/call", { name: "whoami", arguments: {} }), "not-a-real-token");
  assert.equal(response.status, 401);
  assert.match(response.headers.get("www-authenticate"), /error="invalid_token"/);
  assert.equal((await response.text()).includes("result"), false);
});

test("an expired access token is a 401", async () => {
  const { h, token } = await signedIn();
  h.clock.ms += 3600 * 1000 + 1;
  assert.equal((await h.mcp(modernRpc("tools/list"), token)).status, 401);
});

test("a token issued for another resource is refused", async () => {
  const h = harness();
  const token = "minted-for-someone-else";
  await h.store.saveToken({
    hash: crypto.createHash("sha256").update(token).digest("hex"),
    kind: "access", familyId: "f", generation: 0, clientId: "c", user: { id: "u", name: "U" },
    scopes: ["read"], resource: "https://other.example.test/mcp", expiresAt: h.now() + 1e6
  });
  assert.equal((await h.mcp(modernRpc("tools/list"), token)).status, 401);
});

test("a refresh token cannot be spent as a bearer token", async () => {
  const h = harness();
  const { client } = await h.register();
  const issued = await h.tokens(client);
  assert.equal((await h.mcp(modernRpc("tools/list"), issued.refresh_token)).status, 401);
});

test("a token in the query string is not accepted", async () => {
  const { h, token } = await signedIn();
  const message = modernRpc("tools/list");
  const response = await h.call(`/mcp?access_token=${token}`, { method: "POST", headers: modernHeaders(message), body: JSON.stringify(message) });
  assert.equal(response.status, 401);
});

test("insufficient scope is a 403 challenge naming the scope, and the tool does not run", async () => {
  const { h, token } = await signedIn({}, "read");
  const message = modernRpc("tools/call", { name: "remember", arguments: { text: "x" } });
  const response = await h.mcp(message, token);
  assert.equal(response.status, 403);
  const header = response.headers.get("www-authenticate");
  assert.match(header, /error="insufficient_scope"/);
  assert.match(header, /scope="write"/);
  assert.match(header, /resource_metadata=/);
  assert.equal((await response.text()).includes('"result"'), false);
});

test("tool calls are rate limited per token holder", async () => {
  const { h, token } = await signedIn({ toolCallsPerHour: 2 });
  const call = modernRpc("tools/call", { name: "whoami", arguments: {} });
  assert.equal((await h.mcp(call, token)).status, 200);
  assert.equal((await h.mcp(call, token)).status, 200);
  assert.equal((await h.mcp(call, token)).status, 429);
});

/* ---------- Streamable HTTP ---------- */

test("a foreign Origin is a 403, even with a valid token", async () => {
  const { h, token } = await signedIn();
  const message = modernRpc("tools/list");
  const response = await h.mcp(message, token, { ...modernHeaders(message, token), origin: "https://evil.example" });
  assert.equal(response.status, 403);
});

test("the server's own origin and configured origins pass", async () => {
  const { h, token } = await signedIn({ allowedOrigins: ["https://inspector.example.test"] });
  const message = modernRpc("tools/list");
  for (const origin of [ISSUER, "https://inspector.example.test"]) {
    const response = await h.mcp(message, token, { ...modernHeaders(message, token), origin });
    assert.equal(response.status, 200, origin);
  }
});

test("GET and DELETE are 405, and no session id is ever minted", async () => {
  const { h, token } = await signedIn();
  for (const method of ["GET", "DELETE"]) {
    assert.equal((await h.call("/mcp", { method, headers: { authorization: `Bearer ${token}` } })).status, 405);
  }
  const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "c", version: "1" } } };
  const response = await h.mcp(init, token, { "content-type": "application/json", authorization: `Bearer ${token}` });
  assert.equal(response.headers.get("mcp-session-id"), null);
});

test("an oversized body is a 413 and does not reach the parser", async () => {
  const { h, token } = await signedIn();
  const message = modernRpc("tools/call", { name: "whoami", arguments: { pad: "x".repeat(2 * 1024 * 1024) } });
  assert.equal((await h.mcp(message, token)).status, 413);
});

test("malformed JSON and batches are refused", async () => {
  const { h, token } = await signedIn();
  const headers = { "content-type": "application/json", authorization: `Bearer ${token}` };
  const bad = await h.call("/mcp", { method: "POST", headers, body: "{" });
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error.code, -32700);
  const batch = await h.call("/mcp", { method: "POST", headers, body: JSON.stringify([modernRpc("tools/list")]) });
  assert.equal(batch.status, 400);
  assert.equal((await batch.json()).error.code, -32600);
});

test("a null id is refused", async () => {
  const { h, token } = await signedIn();
  const response = await h.mcp({ ...modernRpc("tools/list"), id: null }, token);
  assert.equal((await response.json()).error.code, -32600);
});

/* ---------- 2026-07-28 semantics ---------- */

test("server/discover reports versions and identity with cache hints", async () => {
  const { h, token } = await signedIn();
  const { result } = await (await h.mcp(modernRpc("server/discover"), token)).json();
  assert.equal(result.resultType, "complete");
  assert.ok(result.supportedVersions.includes("2026-07-28"));
  assert.ok(result.capabilities.tools);
  assert.ok(result._meta["io.modelcontextprotocol/serverInfo"].name);
  assert.equal(typeof result.ttlMs, "number");
  assert.ok(["public", "private"].includes(result.cacheScope));
});

test("tools/list carries cache hints and a stable order", async () => {
  const { h, token } = await signedIn();
  const list = async () => (await (await h.mcp(modernRpc("tools/list"), token)).json()).result;
  const first = await list();
  assert.equal(first.resultType, "complete");
  assert.equal(typeof first.ttlMs, "number");
  assert.equal(typeof first.cacheScope, "string");
  assert.deepEqual(first.tools, (await list()).tools);
});

test("a tools/call with a mismatched Mcp-Name is refused before the tool runs", async () => {
  const { h, token } = await signedIn();
  const message = modernRpc("tools/call", { name: "remember", arguments: { text: "x" } });
  const response = await h.mcp(message, token, { ...modernHeaders(message, token), "mcp-name": "whoami" });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, -32020);
});

test("Mcp-Name in the base64 sentinel form is decoded before comparing", async () => {
  const { h, token } = await signedIn();
  const message = modernRpc("tools/call", { name: "whoami", arguments: {} });
  const encoded = `=?base64?${Buffer.from("whoami").toString("base64")}?=`;
  assert.equal((await h.mcp(message, token, { ...modernHeaders(message, token), "mcp-name": encoded })).status, 200);
});

test("Mcp-Method, MCP-Protocol-Version and Mcp-Name mismatches or absences are -32020", async () => {
  const { h, token } = await signedIn();
  const message = modernRpc("tools/call", { name: "whoami", arguments: {} });
  const base = modernHeaders(message, token);
  const without = (key) => Object.fromEntries(Object.entries(base).filter(([k]) => k !== key));
  for (const headers of [
    without("mcp-method"), without("mcp-name"), without("mcp-protocol-version"),
    { ...base, "mcp-method": "tools/list" }, { ...base, "mcp-protocol-version": "2025-11-25" }
  ]) {
    const response = await h.mcp(message, token, headers);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, -32020, JSON.stringify(headers));
  }
});

test("an unsupported version is a 400 that lists the supported ones", async () => {
  const { h, token } = await signedIn();
  const message = modernRpc("tools/list");
  message.params._meta["io.modelcontextprotocol/protocolVersion"] = "1900-01-01";
  const response = await h.mcp(message, token, { ...modernHeaders(message, token), "mcp-protocol-version": "1900-01-01" });
  assert.equal(response.status, 400);
  const { error } = await response.json();
  assert.equal(error.code, -32022);
  assert.equal(error.data.requested, "1900-01-01");
  assert.ok(error.data.supported.includes("2026-07-28"));
});

test("missing required _meta under the modern header is -32602 with status 400", async () => {
  const { h, token } = await signedIn();
  const noVersion = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
  const response = await h.mcp(noVersion, token, modernHeaders(noVersion, token));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, -32602);

  const noCapabilities = modernRpc("tools/list");
  delete noCapabilities.params._meta["io.modelcontextprotocol/clientCapabilities"];
  const second = await h.mcp(noCapabilities, token);
  assert.equal(second.status, 400);
  assert.equal((await second.json()).error.code, -32602);
});

test("an unknown method is a 404 with -32601, and removed methods stay removed", async () => {
  const { h, token } = await signedIn();
  for (const method of ["nope", "ping", "initialize"]) {
    const response = await h.mcp(modernRpc(method), token);
    assert.equal(response.status, 404, method);
    assert.equal((await response.json()).error.code, -32601);
  }
});

test("unknown tools are protocol errors; bad arguments are tool errors the model can read", async () => {
  const { h, token } = await signedIn();
  const unknown = await (await h.mcp(modernRpc("tools/call", { name: "nope", arguments: {} }), token)).json();
  assert.equal(unknown.error.code, -32602);
  const invalid = await (await h.mcp(modernRpc("tools/call", { name: "remember", arguments: { text: 7 } }), token)).json();
  assert.equal(invalid.result.isError, true);
  assert.equal(invalid.result.resultType, "complete");
});

test("arguments that are not an object are a protocol error", async () => {
  const { h, token } = await signedIn();
  const response = await h.mcp(modernRpc("tools/call", { name: "whoami", arguments: "x" }), token);
  assert.equal((await response.json()).error.code, -32602);
});

test("a tool that throws does not leak its error to the caller", async () => {
  const tools = [{ name: "boom", description: "x", scope: "read", inputSchema: { type: "object" }, run() { throw new Error("secret detail"); } }];
  const { h, token } = await signedIn({ tools });
  const original = console.error;
  console.error = () => {};
  const text = await (await h.mcp(modernRpc("tools/call", { name: "boom", arguments: {} }), token)).text();
  console.error = original;
  assert.equal(text.includes("secret detail"), false);
  assert.equal(JSON.parse(text).result.isError, true);
});

test("tools see only their own user's data", async () => {
  const h = harness({
    authenticateUser: ({ form }) => ({ id: form.get("password"), name: form.get("password") })
  });
  const { client } = await h.register();
  const sign = async (user) => {
    const proof = pkce();
    const consent = await h.openConsent(client, proof, { scope: "read write" });
    const redirect = await h.submitConsent(consent, { password: user });
    const code = new URL(redirect.headers.get("location")).searchParams.get("code");
    return (await (await h.exchange(client, code, proof)).json()).access_token;
  };
  const [alice, bob] = [await sign("alice"), await sign("bob")];
  await h.mcp(modernRpc("tools/call", { name: "remember", arguments: { text: "alice note" } }), alice);
  const result = await (await h.mcp(modernRpc("tools/call", { name: "remember", arguments: { text: "bob note" } }), bob)).json();
  assert.deepEqual(result.result.structuredContent.notes, ["bob note"]);
});

/* ---------- legacy clients ---------- */

const legacyHeaders = (token, version) => ({
  "content-type": "application/json",
  authorization: `Bearer ${token}`,
  ...(version ? { "mcp-protocol-version": version } : {})
});

test("initialize negotiates a legacy version and does not claim the stateless one", async () => {
  const { h, token } = await signedIn();
  const init = (protocolVersion) => ({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion, capabilities: {}, clientInfo: { name: "c", version: "1" } } });
  const echoed = await (await h.mcp(init("2025-06-18"), token, legacyHeaders(token))).json();
  assert.equal(echoed.result.protocolVersion, "2025-06-18");
  const fallback = await (await h.mcp(init("2026-07-28"), token, legacyHeaders(token))).json();
  assert.equal(fallback.result.protocolVersion, "2025-11-25");
});

test("legacy tool calls work and carry no 2026 fields; notifications are a 202", async () => {
  const { h, token } = await signedIn();
  const call = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "whoami", arguments: {} } };
  const { result } = await (await h.mcp(call, token, legacyHeaders(token, "2025-11-25"))).json();
  assert.equal(result.resultType, undefined);
  assert.ok(result.content);
  const note = await h.mcp({ jsonrpc: "2.0", method: "notifications/initialized" }, token, legacyHeaders(token, "2025-11-25"));
  assert.equal(note.status, 202);
  assert.equal(await note.text(), "");
});

test("legacy requests still need a token with the right scope and audience", async () => {
  const { h, token } = await signedIn({}, "read");
  const call = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "remember", arguments: { text: "x" } } };
  assert.equal((await h.mcp(call, token, legacyHeaders(token, "2025-11-25"))).status, 403);
  const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: {} };
  assert.equal((await h.mcp(init, "bad", legacyHeaders("bad"))).status, 401);
});
