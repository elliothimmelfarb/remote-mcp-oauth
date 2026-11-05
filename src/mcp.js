// The MCP endpoint: Streamable HTTP, answering every request as one JSON
// object, with no sessions.
//
// It speaks two eras of the protocol. Revision 2026-07-28 is stateless: each
// request carries its version and capabilities in _meta, and mirrors them in
// headers that must match the body. Earlier revisions open with an initialize
// handshake, and those clients are still what most software ships, so a
// request with no _meta version is served under those rules. Nothing about a
// caller is remembered between requests in either era.

import { BodyTooLarge, MAX_BODY_BYTES, json, readBody } from "./http.js";
import { ToolError } from "./tools.js";

export const MODERN_VERSION = "2026-07-28";
export const LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"];
const SUPPORTED = [MODERN_VERSION, ...LEGACY_VERSIONS];

const SERVER_INFO = { name: "remote-mcp-oauth", version: "0.1.0" };
const VERSION_KEY = "io.modelcontextprotocol/protocolVersion";
const CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities";
const SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo";

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;
const HEADER_MISMATCH = -32020;
const UNSUPPORTED_VERSION = -32022;
// Outside the JSON-RPC reserved range, as the spec asks of application codes.
const INSUFFICIENT_SCOPE = -31003;
const RATE_LIMITED = -31029;

class RpcFailure extends Error {
  constructor(status, code, message, data) {
    super(message);
    Object.assign(this, { status, code, data });
  }
}

function rpcError(id, code, message, data) {
  return { jsonrpc: "2.0", ...(id === undefined ? {} : { id }), error: { code, message, ...(data ? { data } : {}) } };
}

function decodeSentinel(value) {
  const match = /^=\?base64\?(.*)\?=$/.exec(value ?? "");
  return match ? Buffer.from(match[1], "base64").toString("utf8") : value;
}

const mismatch = (message) => new RpcFailure(400, HEADER_MISMATCH, message);
const unsupported = (requested) =>
  new RpcFailure(400, UNSUPPORTED_VERSION, "Unsupported protocol version", { supported: SUPPORTED, requested });

// Decides which era a request belongs to, and refuses it if the headers and
// the body disagree. A proxy may route on the headers while this code acts on
// the body, so a disagreement is a security failure and not a formatting one.
function classify(message, headers) {
  const meta = message.params?._meta ?? {};
  const bodyVersion = meta[VERSION_KEY];
  const headerVersion = headers.get("mcp-protocol-version");
  if (bodyVersion === undefined) {
    if (headerVersion === MODERN_VERSION) throw new RpcFailure(400, INVALID_PARAMS, `_meta must carry ${VERSION_KEY}.`);
    if (headerVersion && !LEGACY_VERSIONS.includes(headerVersion)) throw unsupported(headerVersion);
    return "legacy";
  }
  if (typeof bodyVersion !== "string") throw new RpcFailure(400, INVALID_PARAMS, `${VERSION_KEY} must be a string.`);
  if (headerVersion !== bodyVersion) throw mismatch("MCP-Protocol-Version is missing or does not match the body.");
  if (bodyVersion !== MODERN_VERSION) throw unsupported(bodyVersion);
  if (typeof meta[CAPABILITIES_KEY] !== "object" || meta[CAPABILITIES_KEY] === null) {
    throw new RpcFailure(400, INVALID_PARAMS, `_meta must carry ${CAPABILITIES_KEY}.`);
  }
  if (headers.get("mcp-method") !== message.method) throw mismatch("Mcp-Method is missing or does not match the body.");
  if (message.method === "tools/call" && decodeSentinel(headers.get("mcp-name")) !== message.params?.name) {
    throw mismatch("Mcp-Name is missing or does not match the body.");
  }
  return "modern";
}

export function createMcp({ tools, store, oauth, metadataUrl, isAllowedOrigin, defaultScopes, toolCallsPerHour }) {
  const ordered = [...tools].sort((a, b) => a.name.localeCompare(b.name));
  const definitions = ordered.map(({ name, title, description, inputSchema }) => ({ name, title, description, inputSchema }));

  const challenge = (extra) => `Bearer resource_metadata="${metadataUrl}", ${extra}`;

  function unauthorized(hadToken) {
    const scope = `scope="${defaultScopes.join(" ")}"`;
    return json({ error: "unauthorized" }, 401, {
      "www-authenticate": challenge(hadToken ? `error="invalid_token", ${scope}` : scope)
    });
  }

  async function callTool(message, caller) {
    const { params = {} } = message;
    const tool = ordered.find((candidate) => candidate.name === params.name);
    if (!tool) throw new RpcFailure(200, INVALID_PARAMS, "Unknown tool.");
    const args = params.arguments ?? {};
    if (typeof args !== "object" || Array.isArray(args)) throw new RpcFailure(200, INVALID_PARAMS, "arguments must be an object.");
    if (!caller.scopes.includes(tool.scope)) {
      // A 403 rather than a JSON-RPC error, so the client knows to step up.
      throw Object.assign(new RpcFailure(403, INSUFFICIENT_SCOPE, "This token lacks the scope for that tool."), {
        headers: { "www-authenticate": challenge(`error="insufficient_scope", scope="${tool.scope}"`) }
      });
    }
    if (!(await store.allow(`tool:${caller.clientId}:${caller.user.id}`, toolCallsPerHour, 3600))) {
      throw new RpcFailure(429, RATE_LIMITED, "Too many calls this hour.");
    }
    try {
      return await tool.run(args, caller);
    } catch (error) {
      if (error instanceof ToolError) return { content: [{ type: "text", text: error.message }], isError: true };
      console.error("Tool failed", tool.name, error instanceof Error ? error.name : "UnknownError");
      return { content: [{ type: "text", text: "The tool could not complete." }], isError: true };
    }
  }

  function initialize(params) {
    const requested = params?.protocolVersion;
    return {
      protocolVersion: LEGACY_VERSIONS.includes(requested) ? requested : LEGACY_VERSIONS[0],
      capabilities: { tools: { listChanged: false } },
      serverInfo: SERVER_INFO
    };
  }

  async function dispatchLegacy(message, caller) {
    switch (message.method) {
      case "initialize": return initialize(message.params);
      case "ping": return {};
      case "tools/list": return { tools: definitions };
      case "tools/call": return await callTool(message, caller);
      default: throw new RpcFailure(200, METHOD_NOT_FOUND, "Method not found.");
    }
  }

  async function dispatchModern(message, caller) {
    let result;
    switch (message.method) {
      case "server/discover":
        result = { supportedVersions: SUPPORTED, capabilities: { tools: {} }, ttlMs: 3600_000, cacheScope: "public" };
        break;
      case "tools/list":
        result = { tools: definitions, ttlMs: 300_000, cacheScope: "public" };
        break;
      case "tools/call":
        result = await callTool(message, caller);
        break;
      default:
        throw new RpcFailure(404, METHOD_NOT_FOUND, "Method not found.");
    }
    return { resultType: "complete", ...result, _meta: { [SERVER_INFO_KEY]: SERVER_INFO } };
  }

  async function handle(request) {
    const headers = {};
    const origin = request.headers.get("origin");
    if (origin) {
      // DNS rebinding defence, required by the transport.
      if (!isAllowedOrigin(origin)) return json(rpcError(undefined, INVALID_REQUEST, "Origin not allowed."), 403);
      Object.assign(headers, {
        "access-control-allow-origin": origin,
        "access-control-expose-headers": "www-authenticate",
        vary: "origin"
      });
    }
    const withCors = (response) => {
      for (const [key, value] of Object.entries(headers)) response.headers.set(key, value);
      return response;
    };

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-allow-headers": "content-type, authorization, mcp-protocol-version, mcp-method, mcp-name",
          "cache-control": "no-store"
        }
      }));
    }
    if (request.method !== "POST") return withCors(new Response(null, { status: 405, headers: { allow: "POST, OPTIONS" } }));

    // Authenticate before parsing, so a stranger's body is never read.
    const bearer = /^Bearer\s+(\S+)$/i.exec(request.headers.get("authorization") ?? "");
    const caller = bearer ? await oauth.verifyAccessToken(bearer[1]) : null;
    if (!caller) return withCors(unauthorized(Boolean(bearer)));

    let message;
    try {
      message = JSON.parse(await readBody(request, MAX_BODY_BYTES));
    } catch (error) {
      if (error instanceof BodyTooLarge) return withCors(json(rpcError(undefined, INVALID_REQUEST, "Too large."), 413));
      return withCors(json(rpcError(undefined, PARSE_ERROR, "Parse error."), 400));
    }
    if (typeof message !== "object" || message === null || Array.isArray(message) || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
      return withCors(json(rpcError(undefined, INVALID_REQUEST, "Expected one JSON-RPC message."), 400));
    }
    // This server keeps nothing per connection, so notifications need no work.
    if (!("id" in message)) return withCors(new Response(null, { status: 202 }));
    const { id } = message;
    if (typeof id !== "string" && !Number.isInteger(id)) {
      return withCors(json(rpcError(undefined, INVALID_REQUEST, "The id must be a string or an integer."), 400));
    }

    try {
      const era = classify(message, request.headers);
      const result = era === "modern" ? await dispatchModern(message, caller) : await dispatchLegacy(message, caller);
      return withCors(json({ jsonrpc: "2.0", id, result }));
    } catch (error) {
      if (error instanceof RpcFailure) {
        return withCors(json(rpcError(id, error.code, error.message, error.data), error.status, error.headers));
      }
      console.error("MCP request failed", error instanceof Error ? error.name : "UnknownError");
      return withCors(json(rpcError(id, INTERNAL_ERROR, "Internal error."), 500));
    }
  }

  return { handle };
}
