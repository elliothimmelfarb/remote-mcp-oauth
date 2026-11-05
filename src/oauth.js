// The OAuth 2.1 authorization server: metadata, dynamic client registration,
// the authorization endpoint with its consent step, the token endpoint and
// revocation.
//
// Codes live ten minutes and are single use, access tokens last an hour,
// refresh tokens rotate, PKCE S256 is required, and tokens, codes and client
// secrets are stored only as hashes. Every token is bound to this server's
// resource URI, and the MCP endpoint checks that binding.

import crypto from "node:crypto";
import { consentPage, errorPage } from "./consent.js";
import { BodyTooLarge, hasRepeats, json, randomToken, readBody, readCookie, readForm, safeEqual, sha256 } from "./http.js";

export const ACCESS_TTL_SECONDS = 60 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
export const CODE_TTL_SECONDS = 10 * 60;
export const REQUEST_TTL_SECONDS = 10 * 60;

const GRANT_TYPES = ["authorization_code", "refresh_token"];
const AUTH_METHODS = ["none", "client_secret_post", "client_secret_basic"];
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const MAX_STATE_LENGTH = 1024;
const MAX_TOKEN_LENGTH = 512;
const MAX_PASSWORD_TRIES_PER_REQUEST = 5;
const ALL_PASSWORD_TRIES = "consent-global";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, authorization, mcp-protocol-version"
};

export const corsHeaders = CORS;

function parseUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isLoopback(url) {
  return url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
}

function validRedirect(value) {
  const url = typeof value === "string" ? parseUrl(value) : null;
  if (!url || value.includes("#") || url.username || url.password) return false;
  return url.protocol === "https:" || isLoopback(url);
}

// Exact match, with the one exception OAuth 2.1 requires: a loopback redirect
// may use any port, because a native client picks a free one when it starts.
function redirectMatches(registered, presented) {
  if (registered === presented) return true;
  const a = parseUrl(registered);
  const b = typeof presented === "string" ? parseUrl(presented) : null;
  if (!a || !b || !isLoopback(a) || !isLoopback(b)) return false;
  a.port = "";
  b.port = "";
  return a.href === b.href;
}

function clientUrl(redirectUri, issuer, fields) {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(fields)) {
    if (value !== null && value !== undefined) url.searchParams.set(key, value);
  }
  url.searchParams.set("iss", issuer);
  return url;
}

// Only used after a person has seen the redirect host and acted on the page.
function backToClient(redirectUri, issuer, fields) {
  const location = clientUrl(redirectUri, issuer, fields).href;
  return new Response(null, { status: 303, headers: { location, "cache-control": "no-store" } });
}

function tokenError(error, description, status = 400, headers = {}) {
  return json({ error, ...(description ? { error_description: description } : {}) }, status, { ...CORS, ...headers });
}

export function createOAuth({ issuer, resource, store, scopes, defaultScopes, authenticateUser, now }) {
  const scopeKeys = scopes.map((scope) => scope.key);
  const cookieName = issuer.startsWith("https:") ? "__Host-mcp_browser" : "mcp_browser";

  const isThisResource = (value) => value === resource || parseUrl(value)?.href === resource;
  const allResources = (values) => values.every(isThisResource);

  function parseScopes(value) {
    return [...new Set(value.split(/\s+/))].filter((scope) => scopeKeys.includes(scope));
  }

  function metadata() {
    return {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      registration_endpoint: `${issuer}/register`,
      revocation_endpoint: `${issuer}/revoke`,
      scopes_supported: scopeKeys,
      response_types_supported: ["code"],
      grant_types_supported: GRANT_TYPES,
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: AUTH_METHODS,
      revocation_endpoint_auth_methods_supported: AUTH_METHODS,
      authorization_response_iss_parameter_supported: true
    };
  }

  // scopes_supported here is the minimal set for basic use, as the MCP spec
  // asks. Wider scopes arrive through a 403 challenge at the tool that needs
  // them.
  function resourceMetadata() {
    return {
      resource,
      authorization_servers: [issuer],
      scopes_supported: defaultScopes,
      bearer_methods_supported: ["header"]
    };
  }

  /* ---------- registration (RFC 7591) ---------- */

  // Deprecated by MCP 2026-07-28 in favour of Client ID Metadata Documents,
  // and still what clients fall back to when those are not advertised.
  async function register(request, { address }) {
    if (!(await store.allow(`register:${address}`, 20, 3600))) return tokenError("too_many_requests", null, 429);
    let body;
    try {
      body = JSON.parse(await readBody(request, 64 * 1024));
    } catch (error) {
      if (error instanceof BodyTooLarge) throw error;
      return tokenError("invalid_client_metadata", "The body must be JSON.");
    }
    const uris = body?.redirect_uris;
    if (!Array.isArray(uris) || !uris.length || uris.length > 10 || !uris.every(validRedirect)) {
      return tokenError("invalid_redirect_uri", "Between one and ten redirect URIs are required, each https or loopback http, with no fragment.");
    }
    const method = body.token_endpoint_auth_method ?? "none";
    if (!AUTH_METHODS.includes(method)) return tokenError("invalid_client_metadata", "Unsupported token_endpoint_auth_method.");
    const grants = body.grant_types ?? GRANT_TYPES;
    if (!Array.isArray(grants) || !grants.includes("authorization_code") || !grants.every((g) => GRANT_TYPES.includes(g))) {
      return tokenError("invalid_client_metadata", "Unsupported grant_types.");
    }
    if (body.response_types && JSON.stringify(body.response_types) !== '["code"]') {
      return tokenError("invalid_client_metadata", "Only the code response type is supported.");
    }
    const name = typeof body.client_name === "string" && body.client_name.trim() ? body.client_name.trim().slice(0, 120) : "Unnamed client";
    const id = `client_${randomToken(16)}`;
    const secret = method === "none" ? null : randomToken(32);
    await store.saveClient({ id, name, redirectUris: uris, grantTypes: grants, authMethod: method, secretHash: secret ? sha256(secret) : null });
    return json({
      client_id: id,
      client_id_issued_at: Math.floor(now() / 1000),
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
      client_name: name,
      redirect_uris: uris,
      grant_types: grants,
      response_types: ["code"],
      token_endpoint_auth_method: method
    }, 201, CORS);
  }

  /* ---------- authorization ---------- */

  async function authorize(request, { address }) {
    if (!(await store.allow(`authorize:${address}`, 60, 60))) return errorPage("Too many requests. Wait and try again.", 429);
    const params = new URL(request.url).searchParams;
    if (hasRepeats(params, ["resource"])) return errorPage("A parameter appears more than once.");
    const client = await store.getClient(params.get("client_id"));
    if (!client) return errorPage("Unknown client.");
    const redirectUri = params.get("redirect_uri");
    if (!client.redirectUris.some((uri) => redirectMatches(uri, redirectUri))) {
      return errorPage("That redirect address is not registered for this client.");
    }
    const state = params.get("state");
    if (state && state.length > MAX_STATE_LENGTH) return errorPage("The state parameter is too long.");

    // The redirect URI is registered, but registration is open, so that does
    // not make it trustworthy. An automatic redirect here would let anyone use
    // this server as an open redirector, so the person gets a labelled link.
    const fail = (error, description) => {
      const url = clientUrl(redirectUri, issuer, { error, error_description: description, state });
      return errorPage(description ?? error, 400, { href: url.href, host: url.hostname });
    };
    if (params.get("response_type") !== "code") return fail("unsupported_response_type");
    // A missing method means plain, not S256, so it is refused rather than assumed.
    if (params.get("code_challenge_method") !== "S256") return fail("invalid_request", "code_challenge_method must be S256.");
    const challenge = params.get("code_challenge");
    if (!challenge || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) return fail("invalid_request", "A valid S256 code_challenge is required.");
    if (!allResources(params.getAll("resource"))) return fail("invalid_target", "This server issues tokens only for its own resource.");
    const granted = params.get("scope") === null ? defaultScopes : parseScopes(params.get("scope"));
    if (!granted.length) return fail("invalid_scope");

    // The first browser to open a request owns it, so a request minted by an
    // attacker cannot be approved from a victim's browser, or the reverse.
    const existing = readCookie(request, cookieName);
    const browser = existing && /^[A-Za-z0-9_-]{32,64}$/.test(existing) ? existing : randomToken(32);
    const id = randomToken(24);
    await store.saveRequest({
      id,
      clientId: client.id,
      redirectUri,
      scopes: granted,
      challenge,
      state,
      browserHash: sha256(browser),
      expiresAt: now() + REQUEST_TTL_SECONDS * 1000
    });
    const secure = issuer.startsWith("https:") ? "; Secure" : "";
    return consentPage(viewOf({ id, redirectUri, scopes: granted }, client), {
      headers: { "set-cookie": `${cookieName}=${browser}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400${secure}` }
    });
  }

  function viewOf(parked, client, error) {
    const target = new URL(parked.redirectUri);
    return {
      requestId: parked.id,
      clientName: client.name,
      redirectHost: target.hostname,
      loopback: isLoopback(target),
      scopes: scopes.filter((scope) => parked.scopes.includes(scope.key)),
      error
    };
  }

  async function consent(request, { address }) {
    const form = await readForm(request);
    const parked = await store.getRequest(form.get("request_id") ?? "");
    if (!parked || parked.expiresAt <= now()) return errorPage("This request has expired. Start again from the client.");
    const browser = readCookie(request, cookieName);
    if (!browser || !safeEqual(sha256(browser), parked.browserHash)) {
      return errorPage("This request belongs to another browser.", 403);
    }
    if (form.get("decision") === "deny") {
      if (!(await store.takeRequest(parked.id))) return errorPage("This request was already answered.");
      return backToClient(parked.redirectUri, issuer, { error: "access_denied", state: parked.state });
    }
    const client = await store.getClient(parked.clientId);

    // Everything above is free, so a stranger with junk POSTs cannot lock the
    // owner out. A try is counted before the check so that parallel guesses
    // cannot all pass it at once, and given back below if it was right. The
    // global limit is what stops a guesser who has many addresses. It is only
    // reached by a caller still within their own limit, so one address cannot
    // use it up alone.
    const allowed = (await store.allow(`consent:${address}`, 10, 900)) && (await store.allow(ALL_PASSWORD_TRIES, 100, 3600));
    if (!allowed) return errorPage("Too many attempts. Wait and try again.", 429);
    const user = await authenticateUser({ request, form });
    if (!user) {
      if (await store.allow(`consent-request:${parked.id}`, MAX_PASSWORD_TRIES_PER_REQUEST - 1, REQUEST_TTL_SECONDS)) {
        return consentPage(viewOf(parked, client, "That password is not right."), { status: 401 });
      }
      await store.takeRequest(parked.id);
      return errorPage("Too many wrong passwords. Start again from the client.");
    }
    await store.refund(`consent:${address}`);
    await store.refund(ALL_PASSWORD_TRIES);
    // Atomic, so a double submit produces one code.
    if (!(await store.takeRequest(parked.id))) return errorPage("This request was already answered.");
    const code = randomToken(32);
    await store.saveCode({
      hash: sha256(code),
      clientId: parked.clientId,
      redirectUri: parked.redirectUri,
      scopes: parked.scopes,
      challenge: parked.challenge,
      user: { id: user.id, name: user.name },
      familyId: randomToken(16),
      expiresAt: now() + CODE_TTL_SECONDS * 1000
    });
    return backToClient(parked.redirectUri, issuer, { code, state: parked.state });
  }

  /* ---------- token ---------- */

  async function authenticateClient(params, request) {
    let clientId = params.get("client_id");
    let secret = params.get("client_secret");
    const basic = /^Basic\s+(.+)$/i.exec(request.headers.get("authorization") ?? "");
    if (basic) {
      const decoded = Buffer.from(basic[1], "base64").toString("utf8");
      const colon = decoded.indexOf(":");
      if (colon < 0) return null;
      try {
        const basicId = decodeURIComponent(decoded.slice(0, colon));
        if (clientId && clientId !== basicId) return null;
        clientId = basicId;
        secret = decodeURIComponent(decoded.slice(colon + 1));
      } catch {
        return null;
      }
    }
    const client = await store.getClient(clientId);
    if (!client) return null;
    if (client.authMethod === "none") return client;
    return secret && safeEqual(sha256(secret), client.secretHash) ? client : null;
  }

  async function issueTokens(client, { familyId, generation, user, scopes: accessScopes, refreshScopes }) {
    const shared = { familyId, generation, clientId: client.id, user, resource };
    const access = randomToken(32);
    await store.saveToken({ ...shared, hash: sha256(access), kind: "access", scopes: accessScopes, expiresAt: now() + ACCESS_TTL_SECONDS * 1000 });
    let refresh;
    if (client.grantTypes.includes("refresh_token")) {
      refresh = randomToken(32);
      await store.saveToken({ ...shared, hash: sha256(refresh), kind: "refresh", scopes: refreshScopes, expiresAt: now() + REFRESH_TTL_SECONDS * 1000 });
    }
    return json({
      access_token: access,
      token_type: "Bearer",
      expires_in: ACCESS_TTL_SECONDS,
      ...(refresh ? { refresh_token: refresh } : {}),
      scope: accessScopes.join(" ")
    }, 200, CORS);
  }

  async function redeemCode(client, params) {
    const code = params.get("code");
    if (!code || code.length > MAX_TOKEN_LENGTH) return tokenError("invalid_grant");
    if (!allResources(params.getAll("resource"))) return tokenError("invalid_target");
    const row = await store.consumeCode(sha256(code), client.id);
    if (!row) return tokenError("invalid_grant");
    // A second use means the code leaked, so what the first use issued is
    // treated as compromised (OAuth 2.1, section 4.1.3).
    if (!row.firstUse) {
      await store.revokeFamily(row.familyId);
      return tokenError("invalid_grant");
    }
    if (row.expiresAt <= now()) return tokenError("invalid_grant");
    if (row.redirectUri !== params.get("redirect_uri")) return tokenError("invalid_grant", "redirect_uri does not match the authorization request.");
    const verifier = params.get("code_verifier") ?? "";
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return tokenError("invalid_grant", "PKCE verification failed.");
    const computed = crypto.createHash("sha256").update(verifier).digest("base64url");
    if (!safeEqual(computed, row.challenge)) return tokenError("invalid_grant", "PKCE verification failed.");
    return await issueTokens(client, { familyId: row.familyId, generation: 0, user: row.user, scopes: row.scopes, refreshScopes: row.scopes });
  }

  async function redeemRefresh(client, params) {
    const presented = params.get("refresh_token");
    if (!presented || presented.length > MAX_TOKEN_LENGTH) return tokenError("invalid_grant");
    if (!allResources(params.getAll("resource"))) return tokenError("invalid_target");
    const row = await store.getToken(sha256(presented));
    if (!row || row.kind !== "refresh" || row.clientId !== client.id || row.expiresAt <= now()) return tokenError("invalid_grant");
    const requested = params.get("scope");
    const narrowed = requested === null ? row.scopes : parseScopes(requested).filter((scope) => row.scopes.includes(scope));
    if (!narrowed.length) return tokenError("invalid_scope");
    // Compare and swap: of two uses of one token, only the first gets through.
    // The other is either a replay of a stolen token or a client racing
    // itself, and they cannot be told apart, so the family ends.
    const generation = await store.advanceFamily(row.familyId, row.generation);
    if (generation === null) {
      await store.revokeFamily(row.familyId);
      return tokenError("invalid_grant");
    }
    return await issueTokens(client, { familyId: row.familyId, generation, user: row.user, scopes: narrowed, refreshScopes: row.scopes });
  }

  async function token(request, { address }) {
    if (!(await store.allow(`token:${address}`, 120, 900))) return tokenError("too_many_requests", null, 429);
    const params = await readForm(request);
    if (hasRepeats(params, ["resource"])) return tokenError("invalid_request");
    const client = await authenticateClient(params, request);
    if (!client) return tokenError("invalid_client", null, 401, { "www-authenticate": "Basic" });
    const grant = params.get("grant_type");
    if (!client.grantTypes.includes(grant)) return tokenError(GRANT_TYPES.includes(grant) ? "unauthorized_client" : "unsupported_grant_type");
    return grant === "authorization_code" ? await redeemCode(client, params) : await redeemRefresh(client, params);
  }

  /* ---------- revocation (RFC 7009) ---------- */

  async function revoke(request, { address }) {
    if (!(await store.allow(`revoke:${address}`, 120, 900))) return tokenError("too_many_requests", null, 429);
    const params = await readForm(request);
    const client = await authenticateClient(params, request);
    if (!client) return tokenError("invalid_client", null, 401, { "www-authenticate": "Basic" });
    const presented = params.get("token");
    if (presented && presented.length <= MAX_TOKEN_LENGTH) {
      const row = await store.getToken(sha256(presented));
      if (row && row.clientId === client.id) await store.revokeFamily(row.familyId);
    }
    return new Response(null, { status: 200, headers: { ...CORS, "cache-control": "no-store" } });
  }

  /* ---------- the resource server's check ---------- */

  // Returns the caller, or null. Audience is checked here even though this
  // process issued the token: a shared store could hold tokens for others.
  async function verifyAccessToken(presented) {
    if (typeof presented !== "string" || !presented || presented.length > MAX_TOKEN_LENGTH) return null;
    const row = await store.getToken(sha256(presented));
    if (!row || row.kind !== "access" || !row.active || row.expiresAt <= now() || row.resource !== resource) return null;
    return { user: row.user, clientId: row.clientId, scopes: row.scopes };
  }

  return { metadata, resourceMetadata, register, authorize, consent, token, revoke, verifyAccessToken };
}
