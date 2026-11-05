// Small helpers shared by the OAuth and MCP handlers. Everything here works
// with the web standard Request and Response, so the app runs on any runtime
// that has them. src/node.js adapts node:http to that shape.

import crypto from "node:crypto";
import net from "node:net";

export class BodyTooLarge extends Error {}

export const MAX_BODY_BYTES = 1024 * 1024;

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

// Hashing first gives both sides the same length, so the comparison takes the
// same time whatever the input.
export function safeEqual(left, right) {
  return crypto.timingSafeEqual(Buffer.from(sha256(left)), Buffer.from(sha256(right)));
}

// What one caller means to a rate limit. A single IPv6 customer usually holds a
// whole /64, so counting each address separately would let them walk the limit.
export function addressBucket(address) {
  const bare = String(address).split("%")[0];
  if (!net.isIPv6(bare)) return address;
  // The URL parser settles the case, the zeros and any dotted tail.
  const canonical = new URL(`http://[${bare}]`).hostname.slice(1, -1);
  const [left, right] = canonical.split("::").map((side) => (side ? side.split(":") : []));
  const groups = [...left, ...Array(8 - left.length - (right?.length ?? 0)).fill("0"), ...(right ?? [])];
  const mapped = groups.slice(0, 5).every((group) => group === "0") && groups[5] === "ffff";
  if (mapped) {
    const [high, low] = groups.slice(6).map((group) => parseInt(group, 16));
    return [high >> 8, high & 255, low >> 8, low & 255].join(".");
  }
  return `${groups.slice(0, 4).join(":")}::/64`;
}

export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers }
  });
}

export function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      // No script may run, and no other site may frame this page. Framing is
      // how a consent page gets clickjacked. form-action stays unset on
      // purpose: Chrome applies it to the redirect after the POST, which
      // would block the return to the client.
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...headers
    }
  });
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// Reads the body, stopping as soon as it passes the limit rather than after
// the whole thing has been buffered.
export async function readBody(request, limit = MAX_BODY_BYTES) {
  if (!request.body) return "";
  const decoder = new TextDecoder();
  let size = 0;
  let text = "";
  for await (const chunk of request.body) {
    size += chunk.byteLength;
    if (size > limit) throw new BodyTooLarge();
    text += decoder.decode(chunk, { stream: true });
  }
  return text + decoder.decode();
}

export async function readForm(request) {
  return new URLSearchParams(await readBody(request, 64 * 1024));
}

export function readCookie(request, name) {
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

// True when a parameter appears twice. Parsers disagree on which copy wins,
// so OAuth forbids it.
export function hasRepeats(params, except = []) {
  const keys = [...params.keys()].filter((key) => !except.includes(key));
  return new Set(keys).size !== keys.length;
}
