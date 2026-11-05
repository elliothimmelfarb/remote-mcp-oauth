// The page a person sees when a client asks for access, and the default way
// of proving who that person is.
//
// Replace passwordAuthenticator with your own login by passing
// authenticateUser to createApp. It receives { request, form } and returns
// { id, name }, or null to refuse.

import { escapeHtml, html, safeEqual } from "./http.js";

// Only digits, punctuation and spaces, perhaps after a word from the top of
// every leaked password list. Letters from any script count as letters.
const COMMON_PATTERN = /^(?:pass(?:word)?|qwerty(?:uiop)?|letmein|changeme|welcome|admin)?[\p{N}\p{P}\p{S}\p{Z}]*$/iu;

function isEasyToGuess(password) {
  return new Set(password).size < 5 || COMMON_PATTERN.test(password);
}

export function passwordAuthenticator(password, user = { id: "owner", name: "Owner" }) {
  if (typeof password !== "string" || password.length < 12) {
    throw new Error("OWNER_PASSWORD must be at least 12 characters.");
  }
  if (isEasyToGuess(password)) {
    throw new Error("OWNER_PASSWORD is too easy to guess. Use a long phrase or a random value.");
  }
  return ({ form }) => (safeEqual(form.get("password") ?? "", password) ? user : null);
}

const style = `body{font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem;color:#222}
code{background:#eee;padding:.1rem .3rem;border-radius:.2rem}.warn{background:#fff4d6;padding:.6rem .8rem;border-radius:.3rem}
.error{color:#a11}input{font:inherit;width:100%;box-sizing:border-box;padding:.4rem;margin:.3rem 0 1rem}button{font:inherit;padding:.4rem 1rem;margin-right:.5rem}`;

function page(title, body, status, headers) {
  return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>${style}</style></head><body>${body}</body></html>`, status, headers);
}

export function errorPage(message, status = 400, back = null) {
  const link = back ? `<p><a href="${escapeHtml(back.href)}">Return to ${escapeHtml(back.host)}</a></p>` : "";
  return page("Authorization error", `<h1>This request cannot continue</h1><p>${escapeHtml(message)}</p>${link}`, status);
}

export function consentPage({ requestId, clientName, redirectHost, loopback, scopes, error }, { status = 200, headers = {} } = {}) {
  const items = scopes.map((scope) => `<li>${escapeHtml(scope.label)}</li>`).join("");
  return page("Allow access?", `<h1>Allow access?</h1>
<p><strong>${escapeHtml(clientName)}</strong> is asking to act for you. That name is chosen by the client and has not been checked.</p>
<p>The result goes to <code>${escapeHtml(redirectHost)}</code>.</p>
${loopback ? `<p class="warn">That address is on this computer. Any program running here could claim to be this client, so allow it only if you started it yourself.</p>` : ""}
<ul>${items}</ul>
${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
<form method="post" action="/authorize">
<input type="hidden" name="request_id" value="${escapeHtml(requestId)}">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<button name="decision" value="approve">Allow</button>
<button name="decision" value="deny">Deny</button>
</form>`, status, headers);
}
