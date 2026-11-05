// The example server as a real process, since the bugs here are in how
// src/main.js passes configuration along.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";
import { afterEach, test } from "node:test";
import { PASSWORD } from "./helpers.js";

const running = [];

afterEach(() => {
  for (const child of running.splice(0)) child.kill();
});

async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

// Resolves when the server is listening or has exited, whichever comes first.
async function launch(env) {
  const port = await freePort();
  const child = spawn(process.execPath, ["src/main.js"], {
    env: { PATH: process.env.PATH, OWNER_PASSWORD: PASSWORD, PORT: String(port), ...env },
    stdio: ["ignore", "ignore", "pipe"]
  });
  running.push(child);
  let log = "";
  const code = await new Promise((resolve) => {
    child.stderr.on("data", (chunk) => {
      log += chunk;
      if (log.includes("listening on")) resolve(null);
    });
    child.on("exit", resolve);
  });
  return { code, log, port };
}

test("a trailing slash on PUBLIC_URL does not break routing", async () => {
  const { log, port } = await launch({ PUBLIC_URL: "https://mcp.example.test/" });
  assert.match(log, /MCP endpoint: https:\/\/mcp\.example\.test\/mcp /);
  const response = await fetch(`http://127.0.0.1:${port}/.well-known/oauth-authorization-server`);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).issuer, "https://mcp.example.test");
});

test("a non-loopback HOST needs an https PUBLIC_URL", async () => {
  for (const env of [{ HOST: "0.0.0.0" }, { HOST: "0.0.0.0", PUBLIC_URL: "http://127.0.0.1:3000" }]) {
    const { code, log } = await launch(env);
    assert.equal(code, 1, JSON.stringify(env));
    assert.match(log, /PUBLIC_URL/);
  }
});

test("a non-loopback HOST starts once PUBLIC_URL is https", async () => {
  const { code } = await launch({ HOST: "0.0.0.0", PUBLIC_URL: "https://mcp.example.test" });
  assert.equal(code, null);
});

test("the local defaults still start", async () => {
  const { code, log } = await launch({});
  assert.equal(code, null);
  assert.match(log, /http:\/\/127\.0\.0\.1:/);
});
