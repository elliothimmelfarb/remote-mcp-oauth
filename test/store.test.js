// The behaviour a replacement store must keep. Point these at your own store.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryStore } from "../src/index.js";

const token = (fields = {}) => ({
  hash: "h", kind: "access", familyId: "f", generation: 0, clientId: "c",
  user: { id: "u", name: "U" }, scopes: ["read"], resource: "r", expiresAt: 1e15, ...fields
});

test("takeRequest hands a parked request out exactly once", async () => {
  const store = createMemoryStore();
  await store.saveRequest({ id: "r1", expiresAt: 1e15 });
  assert.equal((await store.takeRequest("r1")).id, "r1");
  assert.equal(await store.takeRequest("r1"), null);
});

test("saveRequest keeps at most the cap, dropping the oldest", async () => {
  const store = createMemoryStore({ maxParkedRequests: 2 });
  for (const id of ["r1", "r2", "r3"]) await store.saveRequest({ id, expiresAt: 1e15 });
  assert.equal(await store.getRequest("r1"), null);
  assert.equal((await store.getRequest("r2")).id, "r2");
  assert.equal((await store.getRequest("r3")).id, "r3");
});

test("consumeCode reports first use once, and only for the owning client", async () => {
  const store = createMemoryStore();
  await store.saveCode({ hash: "c1", clientId: "a", expiresAt: 1e15 });
  assert.equal(await store.consumeCode("c1", "b"), null);
  assert.equal((await store.consumeCode("c1", "a")).firstUse, true);
  assert.equal((await store.consumeCode("c1", "a")).firstUse, false);
});

test("advanceFamily lets one of two racers through", async () => {
  const store = createMemoryStore();
  await store.saveToken(token());
  const results = await Promise.all([store.advanceFamily("f", 0), store.advanceFamily("f", 0)]);
  assert.deepEqual(results.sort(), [1, null].sort());
});

test("advancing a family deactivates its older tokens", async () => {
  const store = createMemoryStore();
  await store.saveToken(token());
  await store.advanceFamily("f", 0);
  assert.equal((await store.getToken("h")).active, false);
});

test("a family revoked before its first token is saved stays revoked", async () => {
  const store = createMemoryStore();
  await store.revokeFamily("f");
  await store.saveToken(token());
  assert.equal((await store.getToken("h")).active, false);
  assert.equal(await store.advanceFamily("f", 0), null);
});

test("allow counts inside a window and resets after it", async () => {
  let ms = 0;
  const store = createMemoryStore({ now: () => ms });
  assert.equal(await store.allow("k", 2, 60), true);
  assert.equal(await store.allow("k", 2, 60), true);
  assert.equal(await store.allow("k", 2, 60), false);
  ms = 61_000;
  assert.equal(await store.allow("k", 2, 60), true);
});

test("refund takes one count back", async () => {
  const store = createMemoryStore();
  assert.equal(await store.allow("k", 1, 60), true);
  await store.refund("k");
  assert.equal(await store.allow("k", 1, 60), true);
  assert.equal(await store.allow("k", 1, 60), false);
  await store.refund("never-counted");
});

test("rate limiting alone is enough to purge expired rows", async () => {
  let ms = 0;
  const store = createMemoryStore({ now: () => ms, sweepEveryMs: 0 });
  await store.saveRequest({ id: "old", expiresAt: 10 });
  ms = 100;
  await store.allow("k", 1, 60);
  assert.equal(await store.getRequest("old"), null);
});

test("expired rows are purged, so memory does not grow without bound", async () => {
  let ms = 0;
  const store = createMemoryStore({ now: () => ms, sweepEveryMs: 0 });
  await store.saveRequest({ id: "old", expiresAt: 10 });
  await store.saveToken(token({ expiresAt: 10 }));
  ms = 100 * 24 * 3600 * 1000;
  await store.saveRequest({ id: "new", expiresAt: ms + 10 });
  assert.equal(await store.getRequest("old"), null);
  assert.equal(await store.getToken("h"), null);
});
