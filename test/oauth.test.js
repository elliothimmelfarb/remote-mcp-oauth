import assert from "node:assert/strict";
import { test } from "node:test";
import { ISSUER, PASSWORD, REDIRECT, RESOURCE, harness, modernRpc, pkce } from "./helpers.js";

const body = (response) => response.json();

/* ---------- discovery ---------- */

test("protected resource metadata names the /mcp resource at both well-known paths", async () => {
  const h = harness();
  for (const path of ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]) {
    const doc = await body(await h.call(path));
    assert.equal(doc.resource, RESOURCE);
    assert.deepEqual(doc.authorization_servers, [ISSUER]);
  }
});

test("metadata comes from configuration, never from the Host header", async () => {
  const h = harness();
  const doc = await body(await h.call("/.well-known/oauth-authorization-server", { headers: { host: "evil.example" } }));
  assert.equal(doc.issuer, ISSUER);
  assert.equal(doc.token_endpoint, `${ISSUER}/token`);
});

test("server metadata advertises S256 and iss, and no CIMD it does not implement", async () => {
  const doc = await body(await harness().call("/.well-known/oauth-authorization-server"));
  assert.deepEqual(doc.code_challenge_methods_supported, ["S256"]);
  assert.equal(doc.authorization_response_iss_parameter_supported, true);
  assert.equal(doc.client_id_metadata_document_supported, undefined);
});

/* ---------- registration ---------- */

test("registration refuses redirect URIs that are neither https nor loopback", async () => {
  const h = harness();
  for (const uri of [
    "http://client.example.test/cb",
    "javascript:alert(1)",
    "https://client.example.test/cb#frag",
    "https://user:pass@client.example.test/cb",
    "http://localhost.evil.example/cb",
    "not a url"
  ]) {
    const { response, client } = await h.register({ redirect_uris: [uri] });
    assert.equal(response.status, 400, uri);
    assert.equal(client.error, "invalid_redirect_uri");
  }
});

test("an oversized registration body is refused", async () => {
  const { response } = await harness().register({ client_name: "x".repeat(128 * 1024) });
  assert.equal(response.status, 413);
});

test("one bad URI fails the registration rather than being dropped", async () => {
  const { response } = await harness().register({ redirect_uris: [REDIRECT, "http://evil.example/cb"] });
  assert.equal(response.status, 400);
});

test("registration refuses grant types the server does not implement", async () => {
  const { response, client } = await harness().register({ grant_types: ["client_credentials"] });
  assert.equal(response.status, 400);
  assert.equal(client.error, "invalid_client_metadata");
});

test("a client that did not ask for refresh tokens does not get one", async () => {
  const h = harness();
  const { client } = await h.register({ grant_types: ["authorization_code"] });
  const issued = await h.tokens(client);
  assert.ok(issued.access_token);
  assert.equal(issued.refresh_token, undefined);
});

test("registration is rate limited per address", async () => {
  const h = harness();
  let last;
  for (let i = 0; i < 21; i++) last = (await h.register()).response;
  assert.equal(last.status, 429);
});

/* ---------- authorize ---------- */

test("an unregistered redirect URI gets an error page and is never redirected to", async () => {
  const h = harness();
  const { client } = await h.register();
  const response = await h.call(h.authorizeUrl(client, pkce(), { redirect_uri: "https://evil.example/cb" }));
  assert.equal(response.status, 400);
  assert.equal(response.headers.get("location"), null);
});

test("an unknown client gets an error page and is never redirected", async () => {
  const h = harness();
  const url = h.authorizeUrl({ client_id: "nope", redirect_uris: ["https://evil.example/cb"] }, pkce());
  const response = await h.call(url);
  assert.equal(response.status, 400);
  assert.equal(response.headers.get("location"), null);
});

test("loopback redirects may change port, but nothing else", async () => {
  const h = harness();
  const { client } = await h.register({ redirect_uris: ["http://127.0.0.1:3000/callback"] });
  const same = await h.getCode(client, pkce(), { redirect_uri: "http://127.0.0.1:49152/callback" });
  assert.equal(same.location.port, "49152");
  for (const uri of ["http://127.0.0.1:49152/other", "http://localhost:3000/callback"]) {
    const response = await h.call(h.authorizeUrl(client, pkce(), { redirect_uri: uri }));
    assert.equal(response.status, 400, uri);
  }
});

test("the port exception does not extend to https redirects", async () => {
  const h = harness();
  const { client } = await h.register();
  const response = await h.call(h.authorizeUrl(client, pkce(), { redirect_uri: "https://client.example.test:8443/callback" }));
  assert.equal(response.status, 400);
});

// Registration is open, so a redirect URI proves nothing about who owns it.
// Sending a browser there with no person involved would make this server an
// open redirector, so errors are shown here with a labelled link instead.
const clientError = async (response) => {
  assert.equal(response.status, 400);
  assert.equal(response.headers.get("location"), null);
  const href = /<a href="([^"]+)"/.exec(await response.text())[1].replaceAll("&amp;", "&");
  return new URL(href);
};

test("PKCE is mandatory, S256 only, and a missing method is not read as plain", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const cases = [
    { code_challenge: undefined },
    { code_challenge_method: undefined },
    { code_challenge_method: "plain" },
    { code_challenge: "short" }
  ];
  for (const overrides of cases) {
    const location = await clientError(await h.call(h.authorizeUrl(client, proof, overrides)));
    assert.equal(location.searchParams.get("error"), "invalid_request", JSON.stringify(overrides));
    assert.equal(location.searchParams.get("code"), null);
  }
});

test("an error is never an automatic redirect, and its link carries state and iss", async () => {
  const h = harness();
  const { client } = await h.register({ redirect_uris: ["https://attacker.example/landing"] });
  const location = await clientError(await h.call(h.authorizeUrl(client, pkce(), { response_type: "token" })));
  assert.equal(location.searchParams.get("error"), "unsupported_response_type");
  assert.equal(location.searchParams.get("state"), "state-123");
  assert.equal(location.searchParams.get("iss"), ISSUER);
});

test("a resource other than this server is refused with invalid_target", async () => {
  const h = harness();
  const { client } = await h.register();
  for (const resource of ["https://other.example.test/mcp", `${RESOURCE}/`, `${RESOURCE}#x`]) {
    const location = await clientError(await h.call(h.authorizeUrl(client, pkce(), { resource })));
    assert.equal(location.searchParams.get("error"), "invalid_target", resource);
  }
});

test("repeated parameters are refused, so parsers cannot disagree on which one counts", async () => {
  const h = harness();
  const { client } = await h.register();
  const response = await h.call(`${h.authorizeUrl(client, pkce())}&redirect_uri=${encodeURIComponent("https://evil.example/cb")}`);
  assert.equal(response.status, 400);
  assert.equal(response.headers.get("location"), null);
});

/* ---------- consent ---------- */

test("client-supplied text is escaped on the consent page", async () => {
  const h = harness();
  const { client } = await h.register({ client_name: `<script>alert(1)</script>"` });
  const { html } = await h.openConsent(client, pkce());
  assert.ok(!html.includes("<script>alert(1)"));
});

test("the consent page shows the redirect host and warns about loopback", async () => {
  const h = harness();
  const { client } = await h.register();
  assert.match((await h.openConsent(client, pkce())).html, /client\.example\.test/);
  const { client: local } = await h.register({ redirect_uris: ["http://127.0.0.1:3000/cb"] });
  assert.match((await h.openConsent(local, pkce())).html, /this computer/i);
});

test("the consent page cannot be framed or cached", async () => {
  const h = harness();
  const { client } = await h.register();
  const { response } = await h.openConsent(client, pkce());
  assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("the browser binding cookie is HttpOnly and SameSite=Strict", async () => {
  const h = harness();
  const { client } = await h.register();
  const { response } = await h.openConsent(client, pkce());
  const cookie = response.headers.getSetCookie()[0];
  assert.match(cookie, /^__Host-/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Secure/);
});

test("a wrong password issues no code and leaves the request usable", async () => {
  const h = harness();
  const { client } = await h.register();
  const consent = await h.openConsent(client, pkce());
  const wrong = await h.submitConsent(consent, { password: "wrong" });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.headers.get("location"), null);
  assert.equal((await h.submitConsent(consent, { password: PASSWORD })).status, 303);
});

test("a request cannot be approved from a browser other than the one that opened it", async () => {
  const h = harness();
  const { client } = await h.register();
  const consent = await h.openConsent(client, pkce());
  for (const cookie of ["", "__Host-mcp_browser=attacker"]) {
    const response = await h.submitConsent({ ...consent, cookie });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("location"), null);
  }
  assert.equal((await h.submitConsent(consent)).status, 303);
});

test("double submitting consent issues one code", async () => {
  const h = harness();
  const { client } = await h.register();
  const consent = await h.openConsent(client, pkce());
  assert.equal((await h.submitConsent(consent)).status, 303);
  assert.equal((await h.submitConsent(consent)).status, 400);
});

test("consent attempts are rate limited, which stops password guessing", async () => {
  const h = harness();
  const { client } = await h.register();
  const consent = await h.openConsent(client, pkce());
  let last;
  for (let i = 0; i < 11; i++) last = await h.submitConsent(consent, { password: `guess-${i}` });
  assert.equal(last.status, 429);
});

test("a parked request expires", async () => {
  const h = harness();
  const { client } = await h.register();
  const consent = await h.openConsent(client, pkce());
  h.clock.ms += 11 * 60 * 1000;
  assert.equal((await h.submitConsent(consent)).status, 400);
});

test("denying redirects with access_denied, state and iss, and no code", async () => {
  const h = harness();
  const { client } = await h.register();
  const consent = await h.openConsent(client, pkce());
  const response = await h.submitConsent(consent, { decision: "deny", password: "" });
  const location = new URL(response.headers.get("location"));
  assert.equal(location.searchParams.get("error"), "access_denied");
  assert.equal(location.searchParams.get("state"), "state-123");
  assert.equal(location.searchParams.get("iss"), ISSUER);
  assert.equal(location.searchParams.get("code"), null);
});

/* ---------- token: the three the task names, then the rest ---------- */

test("PKCE mismatch is refused and burns the code", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const wrong = await h.exchange(client, code, pkce());
  assert.equal(wrong.status, 400);
  assert.equal((await wrong.json()).error, "invalid_grant");
  assert.equal((await h.exchange(client, code, proof)).status, 400);
});

test("a verifier that is not valid PKCE syntax is refused", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const response = await h.exchange(client, code, { verifier: "" });
  assert.equal((await response.json()).error, "invalid_grant");
});

test("a redirect URI that differs from the authorize request is refused at the token endpoint", async () => {
  const h = harness();
  const { client } = await h.register({ redirect_uris: [REDIRECT, "https://client.example.test/other"] });
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const response = await h.exchange(client, code, proof, { redirect_uri: "https://client.example.test/other" });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "invalid_grant");
});

test("an expired code is refused, even with the right verifier", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  h.clock.ms += 10 * 60 * 1000 + 1;
  const response = await h.exchange(client, code, proof);
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "invalid_grant");
});

test("replaying a used code is refused and revokes what the first use issued", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const first = await (await h.exchange(client, code, proof)).json();
  assert.equal((await h.mcp(modernRpc("tools/list"), first.access_token)).status, 200);

  const replay = await h.exchange(client, code, proof);
  assert.equal(replay.status, 400);
  assert.equal((await replay.json()).error, "invalid_grant");
  assert.equal((await h.mcp(modernRpc("tools/list"), first.access_token)).status, 401);
  const refresh = await h.form("/token", { grant_type: "refresh_token", client_id: client.client_id, refresh_token: first.refresh_token });
  assert.equal(refresh.status, 400);
});

test("replaying an expired, already used code still revokes", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const first = await (await h.exchange(client, code, proof)).json();
  h.clock.ms += 10 * 60 * 1000 + 1;
  assert.equal((await h.exchange(client, code, proof)).status, 400);
  assert.equal((await h.mcp(modernRpc("tools/list"), first.access_token)).status, 401);
});

test("a code cannot be redeemed by a different client, and the attempt does not burn it", async () => {
  const h = harness();
  const { client } = await h.register();
  const { client: other } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  assert.equal((await h.exchange(other, code, proof)).status, 400);
  assert.equal((await h.exchange(client, code, proof)).status, 200);
});

test("the resource at the token endpoint must match this server", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const response = await h.exchange(client, code, proof, { resource: "https://other.example.test/mcp" });
  assert.equal((await response.json()).error, "invalid_target");
});

test("token responses are never cacheable", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const response = await h.exchange(client, code, proof);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("tokens and codes are stored only as hashes", async () => {
  const h = harness();
  const { client } = await h.register();
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const issued = await (await h.exchange(client, code, proof)).json();
  assert.equal(await h.store.getToken(issued.access_token), null);
  assert.equal(await h.store.consumeCode(code, client.client_id), null);
});

/* ---------- confidential clients ---------- */

test("a confidential client must present its secret, by post or basic", async () => {
  const h = harness();
  const { client } = await h.register({ token_endpoint_auth_method: "client_secret_basic" });
  assert.ok(client.client_secret);
  const proof = pkce();
  const { code } = await h.getCode(client, proof);
  const noSecret = await h.exchange(client, code, proof);
  assert.equal(noSecret.status, 401);
  const wrong = await h.exchange(client, code, proof, { client_secret: "wrong" });
  assert.equal(wrong.status, 401);

  const fresh = pkce();
  const second = await h.getCode(client, fresh);
  const basic = Buffer.from(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`).toString("base64");
  const ok = await h.form(
    "/token",
    { grant_type: "authorization_code", code: second.code, redirect_uri: REDIRECT, code_verifier: fresh.verifier },
    { authorization: `Basic ${basic}` }
  );
  assert.equal(ok.status, 200);
});

/* ---------- refresh and revoke ---------- */

const refresh = (h, client, token, extra = {}) =>
  h.form("/token", { grant_type: "refresh_token", client_id: client.client_id, refresh_token: token, ...extra });

test("refresh rotates: the new pair works and the old access token stops", async () => {
  const h = harness();
  const { client } = await h.register();
  const first = await h.tokens(client);
  const second = await (await refresh(h, client, first.refresh_token)).json();
  assert.notEqual(second.refresh_token, first.refresh_token);
  assert.equal((await h.mcp(modernRpc("tools/list"), second.access_token)).status, 200);
  assert.equal((await h.mcp(modernRpc("tools/list"), first.access_token)).status, 401);
});

test("reusing a rotated refresh token revokes the whole family", async () => {
  const h = harness();
  const { client } = await h.register();
  const first = await h.tokens(client);
  const second = await (await refresh(h, client, first.refresh_token)).json();
  assert.equal((await refresh(h, client, first.refresh_token)).status, 400);
  assert.equal((await h.mcp(modernRpc("tools/list"), second.access_token)).status, 401);
  assert.equal((await refresh(h, client, second.refresh_token)).status, 400);
});

test("two concurrent refreshes cannot both succeed", async () => {
  const h = harness();
  const { client } = await h.register();
  const first = await h.tokens(client);
  const results = await Promise.all([refresh(h, client, first.refresh_token), refresh(h, client, first.refresh_token)]);
  assert.ok(results.filter((r) => r.status === 200).length <= 1);
});

test("refresh cannot widen scope, and a failed widening does not burn the token", async () => {
  const h = harness();
  const { client } = await h.register();
  const first = await h.tokens(client, { scope: "read" });
  const wider = await refresh(h, client, first.refresh_token, { scope: "write" });
  assert.equal((await wider.json()).error, "invalid_scope");
  assert.equal((await refresh(h, client, first.refresh_token)).status, 200);
});

test("a refresh token belongs to its client", async () => {
  const h = harness();
  const { client } = await h.register();
  const { client: other } = await h.register();
  const first = await h.tokens(client);
  assert.equal((await refresh(h, other, first.refresh_token)).status, 400);
  assert.equal((await refresh(h, client, first.refresh_token)).status, 200);
});

test("an expired refresh token is refused", async () => {
  const h = harness();
  const { client } = await h.register();
  const first = await h.tokens(client);
  h.clock.ms += 31 * 24 * 3600 * 1000;
  assert.equal((await refresh(h, client, first.refresh_token)).status, 400);
});

test("an access token cannot be used as a refresh token", async () => {
  const h = harness();
  const { client } = await h.register();
  const first = await h.tokens(client);
  assert.equal((await refresh(h, client, first.access_token)).status, 400);
});

test("revoking ends the family; another client's revoke does nothing", async () => {
  const h = harness();
  const { client } = await h.register();
  const { client: other } = await h.register();
  const issued = await h.tokens(client);
  assert.equal((await h.form("/revoke", { token: issued.access_token, client_id: other.client_id })).status, 200);
  assert.equal((await h.mcp(modernRpc("tools/list"), issued.access_token)).status, 200);
  assert.equal((await h.form("/revoke", { token: issued.refresh_token, client_id: client.client_id })).status, 200);
  assert.equal((await h.mcp(modernRpc("tools/list"), issued.access_token)).status, 401);
});
