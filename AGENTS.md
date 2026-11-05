# remote-mcp-oauth

A minimal remote MCP server with its own OAuth 2.1 authorization server. It has no runtime dependencies and no framework. The README explains what it does and what it leaves out.

## Commands

- `npm test` runs everything. The SDK clients are dev dependencies used only by `test/interop.test.js`.
- `npm start` runs the example server. It needs `OWNER_PASSWORD` in `.env`.

## Rules

- Keep runtime dependencies at zero.
- The target is MCP revision `2026-07-28`, and the `initialize` era must keep working. Read the spec before changing protocol behaviour, and check that the revision is still the current one.
- Test first. Write only tests that would catch a real bug, and keep them small.
- The issuer comes from configuration. Never build a URL from the `Host` or `X-Forwarded-Host` header.
- Never send the browser to a client's redirect URI unless a person has acted on the consent page. Registration is open, so a registered URI proves nothing.
- `takeRequest`, `consumeCode` and `advanceFamily` must stay atomic in any store.
- Count a password failure only after the request ID and cookie have checked out, so that junk POSTs cannot lock the owner out.
- Never log tokens, codes, secrets or query strings. Error logs carry only the error name.
- Do not add a README claim you have not checked against the running server.
- Write prose in plain sentences, with no em dashes and no slogans.
