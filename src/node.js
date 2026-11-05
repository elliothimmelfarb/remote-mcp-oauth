// Adapts the app to node:http.

import { Readable } from "node:stream";

function clientAddress(req, trustProxy) {
  if (trustProxy) {
    // The last entry is the one the nearest proxy added. Earlier entries came
    // from the client and can say anything.
    const forwarded = String(req.headers["x-forwarded-for"] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    if (forwarded.length) return forwarded[forwarded.length - 1];
  }
  return req.socket.remoteAddress ?? "unknown";
}

export function toNodeListener(app, { issuer, trustProxy = false }) {
  return async function listener(req, res) {
    try {
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
      }
      const hasBody = req.method !== "GET" && req.method !== "HEAD";
      // Built on the configured issuer, so the Host header plays no part.
      const request = new Request(issuer + req.url, {
        method: req.method,
        headers,
        ...(hasBody ? { body: Readable.toWeb(req), duplex: "half" } : {})
      });
      const response = await app(request, { address: clientAddress(req, trustProxy) });
      const out = Object.fromEntries(response.headers);
      const cookies = response.headers.getSetCookie();
      if (cookies.length) out["set-cookie"] = cookies;
      res.writeHead(response.status, out);
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      console.error("Listener failed", error instanceof Error ? error.name : "UnknownError");
      if (!res.headersSent) res.writeHead(400);
      res.end();
    }
  };
}
