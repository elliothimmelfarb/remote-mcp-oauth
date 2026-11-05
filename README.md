# remote-mcp-oauth

This is a minimal remote MCP server that is its own OAuth 2.1 authorization server. It uses no web framework and has no runtime dependencies, so you can read the whole flow in about a thousand lines of JavaScript.

Use it to learn how MCP authorization works, or as a starting point you copy and change. It is an example, so read the limits below before you put it on the internet.

## Run it

You need Node 22 or later.

```sh
npm install
cp .env.example .env    # then set OWNER_PASSWORD to at least 12 characters
npm start
```

The MCP endpoint is `http://127.0.0.1:3000/mcp`. Point any MCP client that supports remote servers with OAuth at that URL. The client opens a browser, you type the password on the consent page, and the client gets its tokens.

To run the tests:

```sh
npm test
```

## What it implements

It targets MCP revision `2026-07-28`, the current one when this was written, and the authorization rules that come with it.

| Step | Endpoint | Standard |
| --- | --- | --- |
| Find the authorization server | `/.well-known/oauth-protected-resource/mcp` | RFC 9728 |
| Read its metadata | `/.well-known/oauth-authorization-server` | RFC 8414 |
| Register a client | `POST /register` | RFC 7591 |
| Ask the person | `GET` and `POST /authorize` | OAuth 2.1, PKCE, RFC 9207 |
| Get tokens | `POST /token` | OAuth 2.1, RFC 8707 |
| Revoke tokens | `POST /revoke` | RFC 7009 |
| Call tools | `POST /mcp` | MCP Streamable HTTP |

The behaviour worth knowing about:

- PKCE with S256 is required. A request with no `code_challenge_method` is refused, because the default in OAuth is `plain`.
- Redirect URIs match exactly, except that a loopback address may use any port, which OAuth 2.1 requires.
- Authorization codes last ten minutes and work once. Using a code twice revokes the tokens it produced.
- Access tokens last an hour. Refresh tokens rotate, and reusing an old one revokes the whole family.
- Each token is bound to this server's resource URI, and `/mcp` checks that binding on every call.
- Tokens, codes and client secrets are stored only as SHA-256 hashes. Each is 256 bits of randomness, so a slow hash adds nothing.
- A tool call without the scope it needs gets a 403 with a `WWW-Authenticate` challenge, so the client can ask for more.
- The issuer comes from configuration and never from the `Host` header.
- `GET /authorize` is limited to 60 requests a minute per address, and at most 1000 requests wait for consent at once. Past that the oldest is dropped.
- Ten wrong passwords in 15 minutes block an address, 100 in an hour across all addresses block everyone, and five on one consent request end that request. All IPv6 addresses in a /64 count as one address. Only a wrong password on a live request from the browser that opened it counts, so junk POSTs cannot lock the owner out.
- The default login refuses to start with a password under 12 characters or one that is easy to guess, such as `aaaaaaaaaaaa` or `password1234`.
- An authorization error is shown on a page with a link back to the client. It is not an automatic redirect, because registration is open and an automatic redirect would make this an open redirector.

## Two protocol eras

Revision `2026-07-28` removed the `initialize` handshake, so every request now carries its version and capabilities. Many clients still use the older handshake. Version 1 of the official TypeScript SDK only speaks that, and version 2 only speaks the new revision when asked. This server answers both, and it keeps no sessions in either case. A request with `_meta` version information is served as `2026-07-28`, and any other request is served under the rules of `2025-11-25`, `2025-06-18` or `2025-03-26`.

`server/discover` needs a token like every other method. The spec does not say whether it should, and keeping one rule means the server never parses a stranger's body.

## Code layout

| File | What it holds |
| --- | --- |
| `src/app.js` | Configuration and routing |
| `src/oauth.js` | The authorization server |
| `src/consent.js` | The consent page and the default login |
| `src/mcp.js` | The `/mcp` endpoint and both protocol eras |
| `src/store.js` | The storage interface and the in-memory default |
| `src/tools.js` | Two example tools |
| `src/http.js` | Shared helpers |
| `src/node.js` | The adapter from `node:http` to `Request` and `Response` |
| `src/main.js` | The example server |

`createApp` returns a function from `Request` to `Response`, so it can run on any runtime that has those. You pass the caller's address as `app(request, { address })` for rate limiting.

## Making it yours

**Tools.** Pass your own `tools`, `scopes` and `defaultScopes` to `createApp`. `src/tools.js` shows the shape. Validate arguments inside each tool, because nothing here checks them against `inputSchema`.

**Login.** Pass your own `authenticateUser`. It receives `{ request, form }` and returns `{ id, name }`, or `null` to refuse. The default is one shared password, which suits a personal server and nothing else.

**Storage.** Pass your own `store`. The comment at the top of `src/store.js` describes the interface, and `test/store.test.js` is the contract. Three methods must be atomic: `takeRequest`, `consumeCode` and `advanceFamily`. If you write them as a read followed by a write, a code or refresh token can be spent twice.

## Limits

These were left out on purpose. Check each one before you deploy this.

- **Client ID Metadata Documents are not implemented.** `2026-07-28` deprecates dynamic client registration in favour of them, and says servers should support them. Clients still fall back to registration, because the server does not advertise the newer option. Adding them means fetching URLs that clients choose, so you would need to defend against server-side request forgery.
- **Storage is in memory.** A restart loses every client and token, and the store only works for a single process. Its atomicity comes from Node running one thing at a time.
- **Registration is open.** Anyone can register a client, limited to 20 an hour per address. Registered clients are never deleted, so a patient caller can grow memory without limit.
- **Rate limits need a real address.** Behind a reverse proxy, set `TRUST_PROXY=1`. With it unset, every caller looks like the proxy, so they all share one bucket. Ten wrong passwords from anyone then block the consent page for everyone for the rest of those 15 minutes, including the owner with the right password, and 60 `GET /authorize` calls in a minute or 20 registrations in an hour do the same to those endpoints. Set it only when exactly one proxy sits in front of the server, because the header can otherwise be forged.
- **The global password limit can be used against you.** Someone with enough addresses can spend all 100 tries and keep the owner out until the hour ends. That is the price of bounding guesses from many addresses. A real login behind `authenticateUser` is the way out, and the default password suits a personal server and nothing else.
- **Redirect URIs must be https or loopback,** as the spec requires. Clients that use a custom scheme such as `myapp://` cannot register.
- **A refresh race ends the session.** Two simultaneous refreshes with one token look the same as a stolen token, so the family is revoked and the person signs in again.
- **Consent is asked every time.** Nothing remembers an earlier approval.
- **There are no streams.** Every response is a single JSON object, there is no `subscriptions/listen`, and lists are not paginated.

## License

MIT. See [LICENSE](LICENSE).
