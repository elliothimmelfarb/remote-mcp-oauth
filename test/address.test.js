import assert from "node:assert/strict";
import { test } from "node:test";
import { addressBucket } from "../src/http.js";

test("every address in one IPv6 /64 lands in one bucket, however it is written", () => {
  const bucket = addressBucket("2001:db8:1:2::1");
  for (const address of ["2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:0DB8:0001:0002:0:0:0:9", "2001:db8:1:2::1%eth0"]) {
    assert.equal(addressBucket(address), bucket, address);
  }
});

test("neighbouring /64s stay apart", () => {
  assert.notEqual(addressBucket("2001:db8:1:2::1"), addressBucket("2001:db8:1:3::1"));
});

test("an IPv4 client on a dual stack socket counts as its IPv4 address", () => {
  assert.equal(addressBucket("::ffff:203.0.113.7"), "203.0.113.7");
});

test("IPv4 addresses and anything unparseable pass through unchanged", () => {
  assert.equal(addressBucket("203.0.113.7"), "203.0.113.7");
  assert.equal(addressBucket("unknown"), "unknown");
});
