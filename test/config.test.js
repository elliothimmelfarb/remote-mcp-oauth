import assert from "node:assert/strict";
import { test } from "node:test";
import { createApp, passwordAuthenticator } from "../src/index.js";

const authenticateUser = () => null;

test("a non-loopback issuer must be https", () => {
  assert.throws(() => createApp({ issuer: "http://mcp.example.test", authenticateUser }), /https/);
});

test("a loopback issuer may be http", () => {
  assert.doesNotThrow(() => createApp({ issuer: "http://127.0.0.1:3000", authenticateUser }));
});

test("an issuer with a path is refused", () => {
  assert.throws(() => createApp({ issuer: "https://mcp.example.test/base", authenticateUser }), /path/);
});

test("the app refuses to start with no way to authenticate a person", () => {
  assert.throws(() => createApp({ issuer: "https://mcp.example.test" }), /authenticateUser/);
});

test("the default authenticator refuses a short password at startup", () => {
  assert.throws(() => passwordAuthenticator("short"), /12/);
  assert.throws(() => passwordAuthenticator(undefined), /12/);
});

test("the default authenticator refuses an obviously weak password at startup", () => {
  const commonWords = ["pass" + "word", "qwerty" + "uiop"].map((word) => `${word}1234`.slice(0, 12));
  for (const value of ["aaaaaaaaaaaa", "abababababab", "abcdabcdabcd", "123456789012", "            ", ...commonWords]) {
    assert.throws(() => passwordAuthenticator(value), /easy to guess/, value);
  }
});

test("the default authenticator accepts a long or random password, in any script", () => {
  for (const password of ["correct horse battery", "x7#kQ2!mZp9L", "дежурный-пароль"]) {
    assert.doesNotThrow(() => passwordAuthenticator(password), password);
  }
});
