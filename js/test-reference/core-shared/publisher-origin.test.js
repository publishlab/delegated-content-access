import { describe } from "node:test";
import assert from "node:assert/strict";

import { normalizePublisherOrigin } from "../../core-shared/publisherOrigin.js";
import { test, portableTest } from "../support/portable-test.js";

const portableCoreTest = portableTest("portable-core");

/**
 * Values that are not an origin, or carry more than one. The direct case adds
 * `undefined`, which no reference API takes across the bridge, so its portable
 * twin reads this list alone.
 */
const NOT_CANONICAL = [
  null,
  42,
  {},
  [],
  "",
  "null",
  "publisher.example",
  " https://publisher.example",
  "https://publisher.example ",
  "\thttps://publisher.example\t",
  "HTTPS://publisher.example",
  "https://publisher.example/",
  "https://publisher.example:443",
  "https://publisher.example.",
  "https://publisher.example.:8443",
  "https://publisher.example:0",
  "https://[::1]:0",
  "https://user@publisher.example",
  "https://publisher.example/path",
  "https://publisher.example?query",
  "https://publisher.example#fragment",
  "ftp://publisher.example",
];

describe("canonical publisher origin", () => {
  portableCoreTest("accepts an exact HTTP(S) origin without changing its spelling", () => {
    for (const origin of [
      "https://publisher.example",
      "http://localhost:8080",
      "https://publisher.example:8443",
      "https://publisher.example:1",
      "https://publisher.example:65535",
    ]) {
      assert.equal(normalizePublisherOrigin(origin), origin);
    }
  });

  test("refuses aliases and values carrying anything beyond an origin", () => {
    for (const value of [undefined, ...NOT_CANONICAL]) {
      assert.equal(
        normalizePublisherOrigin(value),
        null,
        `${JSON.stringify(value)} is not canonical`,
      );
    }
  });

  portableCoreTest(
    "refuses aliases and values carrying anything beyond an origin, undefined aside",
    () => {
      for (const value of NOT_CANONICAL) {
        assert.equal(
          normalizePublisherOrigin(value),
          null,
          `${JSON.stringify(value)} is not canonical`,
        );
      }
    },
  );

  portableCoreTest("accepts a bracketed IPv6 literal in the one spelling a browser sends", () => {
    // Brackets, lowercase hexadecimal, no leading zero in a piece, and `::`
    // over the leftmost longest run of two or more zero pieces. Address
    // class decides nothing: a global, link-local, unique-local,
    // unspecified, multicast or IPv4-mapped literal is a host coordinate
    // like any other, and the mapped one is hexadecimal because that is
    // what the URL serializer writes.
    for (const origin of [
      "https://[2001:db8::1]",
      "https://[2001:db8::1]:8443",
      "https://[::1]",
      "https://[::]",
      "https://[fe80::1]",
      "https://[fd00::1]",
      "https://[ff02::1]",
      "https://[::ffff:7f00:1]",
      "https://[::d01:4403]",
      "https://[1::1:0:0:1:1]",
      "https://[::1:0:0:0:1]",
      "https://[1:0:0:1::1]",
      "https://[1:0:1:1:1:1:1:1]",
      "https://[1::1]",
      "https://[2001:db8::1:0:0:1]",
    ]) {
      assert.equal(normalizePublisherOrigin(origin), origin);
    }
  });

  portableCoreTest("refuses every other spelling of a literal, foldable or malformed", () => {
    // This side folds nothing. A value the URL parser would have rewritten
    // is not a value a browser reports, so it is refused rather than
    // reduced, and a zone identifier or IPvFuture syntax never parses at
    // all. PHP `Origin::canonical` folds the foldable ones on configured
    // publisher input and `Origin::observed` refuses them on a header.
    for (const value of [
      "https://[2001:DB8::1]",
      "https://[2001:0db8:0000:0000:0000:0000:0000:0001]",
      "https://[2001:db8:0:0:0:0:0:1]",
      "https://[2001:db8::0:1]",
      "https://[2001:db8::1]:443",
      "https://[2001:db8::1]/",
      "https://[::ffff:127.0.0.1]",
      "https://[::13.1.68.3]",
      "https://[0:0:0:0:0:0:0:0]",
      "https://[fe80::1%25eth0]",
      "https://[fe80::1%eth0]",
      "https://[v7.abc]",
      "https://[2001:db8::1",
      "https://2001:db8::1]",
      "https://[2001:db8::1].",
      "https://[2001:db8::1]x",
      "https://[::1][::2]",
      "https://[]",
      "https://[2001:db8:::1]",
      "https://[:2001:db8::1]",
      "https://[2001:db8::1:]",
      "https://[2001:gb8::1]",
      "https://[12345::1]",
      "https://[2001:db8:1:2:3:4:5:6:7]",
      "https://[2001:db8:1:2:3:4:5]",
      "https://[::ffff:256.0.0.1]",
      "https://[::ffff:127.0.0.01]",
      "https://[::ffff:1.2.3]",
      "https://[::1.2.3.4.5]",
      "https://[1:2:3:4:5:6:7:8.9.10.11]",
    ]) {
      assert.equal(
        normalizePublisherOrigin(value),
        null,
        `${JSON.stringify(value)} is not canonical`,
      );
    }
  });
});
