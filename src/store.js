// The storage interface and its in-memory default.
//
// Replace this with your own database by implementing the same methods. The
// tests in test/store.test.js state the behaviour that matters. Three methods
// must be atomic, because they are what stops a code or refresh token being
// spent twice:
//
//   takeRequest(id)                    delete and return a parked request
//   consumeCode(hash, clientId)        mark used, report whether this was first
//   advanceFamily(familyId, generation) compare and swap on the generation
//
// In SQL these are a DELETE ... RETURNING, an UPDATE ... RETURNING and a
// conditional UPDATE. A read followed by a write is not enough.
//
// Token families: every grant has a family id and a generation. A token is
// active while its family is not revoked and its generation is the family's
// current one, so a rotation retires the previous pair with one write.
//
// getToken returns the row plus `active`. allow(key, limit, windowSeconds) is
// a fixed window rate limit that counts every call, and refund(key) takes one
// count back. Both must be atomic. Every method may be async. Expiry is checked
// by the caller, so purging is housekeeping and never a security control.
//
// saveRequest must also bound how many requests are parked, because anyone can
// park one without signing in. Past the cap it drops the oldest rather than
// refusing the newest, so that a flood delays the owner but cannot shut them out.

const DAY_MS = 24 * 3600 * 1000;

export function createMemoryStore({ now = Date.now, sweepEveryMs = 60_000, maxParkedRequests = 1000 } = {}) {
  const clients = new Map();
  const requests = new Map();
  const codes = new Map();
  const tokens = new Map();
  const families = new Map();
  const rates = new Map();
  let lastSweep = now();

  function sweep() {
    const time = now();
    if (time - lastSweep < sweepEveryMs) return;
    lastSweep = time;
    for (const map of [requests, tokens, families, rates]) {
      for (const [key, row] of map) if (row.expiresAt <= time) map.delete(key);
    }
    // Used codes outlive their expiry so a late replay is still detected.
    for (const [key, row] of codes) if (row.expiresAt + DAY_MS <= time) codes.delete(key);
  }

  function family(id) {
    if (!families.has(id)) families.set(id, { generation: 0, revoked: false, expiresAt: now() + DAY_MS });
    return families.get(id);
  }

  return {
    async saveClient(client) {
      sweep();
      clients.set(client.id, client);
    },
    async getClient(id) {
      return clients.get(id) ?? null;
    },

    async saveRequest(request) {
      sweep();
      requests.set(request.id, request);
      // A Map keeps insertion order, so the first key is the oldest.
      if (requests.size > maxParkedRequests) requests.delete(requests.keys().next().value);
    },
    async getRequest(id) {
      return requests.get(id) ?? null;
    },
    async takeRequest(id) {
      const request = requests.get(id) ?? null;
      requests.delete(id);
      return request;
    },

    async saveCode(code) {
      sweep();
      codes.set(code.hash, { ...code, used: false });
    },
    async consumeCode(hash, clientId) {
      const code = codes.get(hash);
      if (!code || code.clientId !== clientId) return null;
      const firstUse = !code.used;
      code.used = true;
      return { ...code, firstUse };
    },

    async saveToken(token) {
      sweep();
      tokens.set(token.hash, token);
      const row = family(token.familyId);
      row.expiresAt = Math.max(row.expiresAt, token.expiresAt);
    },
    async getToken(hash) {
      const token = tokens.get(hash);
      if (!token) return null;
      const row = family(token.familyId);
      return { ...token, active: !row.revoked && row.generation === token.generation };
    },
    async advanceFamily(familyId, generation) {
      const row = family(familyId);
      if (row.revoked || row.generation !== generation) return null;
      row.generation += 1;
      return row.generation;
    },
    async revokeFamily(familyId) {
      family(familyId).revoked = true;
    },

    async allow(key, limit, windowSeconds) {
      sweep();
      const time = now();
      const windowMs = windowSeconds * 1000;
      let row = rates.get(key);
      if (!row || row.start + windowMs <= time) {
        row = { start: time, count: 0, expiresAt: time + windowMs };
        rates.set(key, row);
      }
      row.count += 1;
      return row.count <= limit;
    },
    async refund(key) {
      const row = rates.get(key);
      if (row) row.count -= 1;
    }
  };
}
