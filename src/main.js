// Runs the example server from environment variables.

import http from "node:http";
import { createApp, parseIssuer, passwordAuthenticator, toNodeListener } from "./index.js";

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 3000);
const isLoopback = host === "localhost" || host === "::1" || host.startsWith("127.");

try {
  const issuer = parseIssuer(process.env.PUBLIC_URL || `http://127.0.0.1:${port}`);
  // Passwords and tokens would otherwise cross the network unencrypted.
  if (!isLoopback && !issuer.startsWith("https:")) {
    throw new Error(`HOST is ${host}, which is reachable from other machines, so PUBLIC_URL must be an https URL.`);
  }
  const app = createApp({
    issuer,
    authenticateUser: passwordAuthenticator(process.env.OWNER_PASSWORD),
    allowedOrigins: (process.env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean)
  });
  const listener = toNodeListener(app, { issuer, trustProxy: process.env.TRUST_PROXY === "1" });
  http.createServer(listener).listen(port, host, () => {
    console.error(`MCP endpoint: ${issuer}/mcp (listening on ${host}:${port})`);
  });
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
