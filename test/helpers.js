import crypto from "node:crypto";
import { createApp, createMemoryStore, passwordAuthenticator } from "../src/index.js";

export const ISSUER = "https://mcp.example.test";
export const RESOURCE = `${ISSUER}/mcp`;
export const PASSWORD = "correct horse battery";
export const REDIRECT = "https://client.example.test/callback";
export const MODERN = "2026-07-28";

export function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  return { verifier, challenge: crypto.createHash("sha256").update(verifier).digest("base64url") };
}

export function modernRpc(method, params = {}, id = 1) {
  return {
    jsonrpc: "2.0",
    id,
    method,
    params: {
      ...params,
      _meta: {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientCapabilities": {}
      }
    }
  };
}

export function modernHeaders(message, token) {
  return {
    "content-type": "application/json",
    "mcp-protocol-version": MODERN,
    "mcp-method": message.method,
    ...(message.params?.name ? { "mcp-name": message.params.name } : {}),
    ...(token ? { authorization: `Bearer ${token}` } : {})
  };
}

// An app with a fake clock, driven in process so tests can move time and
// reach into the store.
export function harness(options = {}) {
  const clock = { ms: Date.parse("2026-11-05T12:00:00Z") };
  const now = () => clock.ms;
  const store = createMemoryStore({ now });
  const app = createApp({
    issuer: ISSUER,
    store,
    now,
    authenticateUser: passwordAuthenticator(PASSWORD),
    ...options
  });
  const call = (path, init = {}, address = "203.0.113.1") =>
    app(new Request(ISSUER + path, init), { address });

  const form = (path, fields, headers = {}) =>
    call(path, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
      body: new URLSearchParams(fields)
    });

  async function register(body = {}) {
    const response = await call("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_name: "Test", redirect_uris: [REDIRECT], ...body })
    });
    return { response, client: await response.clone().json().catch(() => ({})) };
  }

  function authorizeUrl(client, proof, overrides = {}) {
    const params = {
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      code_challenge: proof.challenge,
      code_challenge_method: "S256",
      state: "state-123",
      scope: "read",
      resource: RESOURCE,
      ...overrides
    };
    for (const key of Object.keys(params)) if (params[key] === undefined) delete params[key];
    return `/authorize?${new URLSearchParams(params)}`;
  }

  // GET the consent page, returning what a browser holds afterwards.
  async function openConsent(client, proof, overrides = {}) {
    const response = await call(authorizeUrl(client, proof, overrides));
    const html = await response.clone().text();
    const requestId = /name="request_id" value="([^"]+)"/.exec(html)?.[1];
    const cookie = (response.headers.getSetCookie()[0] || "").split(";")[0];
    return { response, html, requestId, cookie };
  }

  async function submitConsent({ requestId, cookie }, fields = {}) {
    return form(
      "/authorize",
      { request_id: requestId, decision: "approve", password: PASSWORD, ...fields },
      { cookie }
    );
  }

  // Everything up to the redirect back to the client.
  async function getCode(client, proof, overrides = {}) {
    const consent = await openConsent(client, proof, overrides);
    const response = await submitConsent(consent);
    const location = new URL(response.headers.get("location"));
    return { code: location.searchParams.get("code"), location, response };
  }

  const exchange = (client, code, proof, overrides = {}) =>
    form("/token", {
      grant_type: "authorization_code",
      client_id: client.client_id,
      code,
      redirect_uri: client.redirect_uris[0],
      code_verifier: proof.verifier,
      resource: RESOURCE,
      ...overrides
    });

  async function tokens(client, overrides = {}) {
    const proof = pkce();
    const { code } = await getCode(client, proof, overrides);
    const response = await exchange(client, code, proof);
    return await response.json();
  }

  async function mcp(message, token, headers) {
    return call("/mcp", {
      method: "POST",
      headers: headers || modernHeaders(message, token),
      body: JSON.stringify(message)
    });
  }

  return {
    app, call, clock, exchange, form, getCode, mcp, now, openConsent, register, store,
    submitConsent, tokens, authorizeUrl
  };
}
