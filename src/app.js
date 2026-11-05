// createApp wires the pieces together and returns a function from a web
// standard Request to a Response. The second argument carries the caller's
// address for rate limiting.

import { errorPage } from "./consent.js";
import { BodyTooLarge, addressBucket, json } from "./http.js";
import { createMcp } from "./mcp.js";
import { corsHeaders, createOAuth } from "./oauth.js";
import { createMemoryStore } from "./store.js";
import { DEFAULT_SCOPES, SCOPES, createExampleTools } from "./tools.js";

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

// The issuer comes from configuration and never from the Host header. Deriving
// it from a request would let anyone who can set that header rewrite the
// endpoints a client discovers.
function parseIssuer(value) {
  const url = new URL(value);
  if (url.pathname !== "/" || url.search || url.hash) throw new Error("The issuer must be an origin with no path.");
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) {
    throw new Error("The issuer must be https, unless it is a loopback address.");
  }
  return url.origin;
}

export function createApp({
  issuer: configuredIssuer,
  authenticateUser,
  store = createMemoryStore(),
  tools = createExampleTools(),
  scopes = SCOPES,
  defaultScopes = DEFAULT_SCOPES,
  allowedOrigins = [],
  toolCallsPerHour = 300,
  now = Date.now
}) {
  if (typeof authenticateUser !== "function") throw new Error("createApp needs authenticateUser.");
  const issuer = parseIssuer(configuredIssuer);
  const resource = `${issuer}/mcp`;
  const metadataUrl = `${issuer}/.well-known/oauth-protected-resource/mcp`;
  const origins = new Set([issuer, ...allowedOrigins]);

  const oauth = createOAuth({ issuer, resource, store, scopes, defaultScopes, authenticateUser, now });
  const mcp = createMcp({
    tools, store, oauth, metadataUrl, defaultScopes, toolCallsPerHour,
    isAllowedOrigin: (origin) => origins.has(origin)
  });

  const publicJson = (body) => json(body, 200, { ...corsHeaders, "cache-control": "public, max-age=3600" });

  function route(method, path) {
    if (path === "/mcp") return mcp.handle;
    if (method === "OPTIONS") return () => new Response(null, { status: 204, headers: corsHeaders });
    const key = `${method} ${path}`;
    switch (key) {
      case "GET /.well-known/oauth-protected-resource":
      case "GET /.well-known/oauth-protected-resource/mcp":
        return () => publicJson(oauth.resourceMetadata());
      case "GET /.well-known/oauth-authorization-server":
        return () => publicJson(oauth.metadata());
      case "POST /register": return oauth.register;
      case "GET /authorize": return oauth.authorize;
      case "POST /authorize": return oauth.consent;
      case "POST /token": return oauth.token;
      case "POST /revoke": return oauth.revoke;
      default: return () => json({ error: "not_found" }, 404);
    }
  }

  return async function app(request, { address = "unknown" } = {}) {
    try {
      return await route(request.method, new URL(request.url).pathname)(request, { address: addressBucket(address) });
    } catch (error) {
      if (error instanceof BodyTooLarge) return errorPage("That request is too large.", 413);
      console.error("Request failed", error instanceof Error ? error.name : "UnknownError");
      return json({ error: "server_error" }, 500);
    }
  };
}
