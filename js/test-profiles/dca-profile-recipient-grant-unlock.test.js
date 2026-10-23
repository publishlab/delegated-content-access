import test from "node:test";
import assert from "node:assert/strict";
import { createBrowserClient } from "../integration-client/createBrowserClient.js";
import { createIssuerCore } from "../integration-issuer/createIssuerCore.js";
import {
  world,
  client,
  opened,
  SELECTION,
  URL,
  REFERENCE,
} from "../extensions/recipient-grant/test/client-fixture.js";

test("recipient browser presents one bearer to the trusted issuer and opens changed same-name items on later renders", async () => {
  const w = await world();
  for (const text of ["first article text", "changed article under the same granted name"]) {
    const { root } = await w.render(text);
    const c = client(root, w.fetch);
    const result = await c.unlock(["body", "extra", "new_item"]);
    assert.equal(result.status, 200);
    assert.equal(result.application.accepted, 1);
    assert.equal(await opened(c), text);
    assert.equal(await c.resolver.contentKeyFor(c.dcaData, "extra"), null);
    assert.equal(await c.resolver.contentKeyFor(c.dcaData, "new_item"), null);
  }
  assert.equal(w.calls.length, 2);
  for (const [index, { url, init, request }] of w.calls.entries()) {
    assert.equal(url, URL);
    assert.equal(init.method, "POST");
    assert.equal(init.credentials, "omit");
    assert.equal(init.redirect, "error");
    assert.deepEqual(init.headers, {
      Authorization: `Bearer ${REFERENCE}`,
      "Content-Type": "application/json",
    });
    assert.equal(request.issuerName, SELECTION.issuerName);
    assert.deepEqual(Object.keys(request.sealed), ["contentKeys"]);
    assert.deepEqual(
      request.sealed.contentKeys.map((/** @type {any} */ record) => record.contentName),
      index === 0 ? ["body", "extra"] : ["body", "extra", "new_item"],
    );
    assert.equal(Object.hasOwn(request, "shareGrant"), false);
    assert.equal(init.body.includes(REFERENCE), false);
  }
});

test("a refused grant leaves an independently selected ordinary login attempt available", async () => {
  const w = await world();
  const { root } = await w.render();
  w.grant.revoked = true;
  const grantClient = client(root, w.fetch);
  const refused = await grantClient.unlock(["body"]);
  assert.equal(refused.status, 401);
  assert.equal(w.calls.length, 1);

  const ordinaryCore = createIssuerCore({
    operatingIssuerNames: [SELECTION.issuerName],
    accessPolicy: {
      decide(_claims, requested, input) {
        assert.deepEqual(input.principal, { kind: "login", id: "reader" });
        return { contentNames: requested.contentNames, periodGrants: [] };
      },
    },
  });
  const ordinaryCalls = [];
  const ordinary = createBrowserClient({
    root,
    issuerName: SELECTION.issuerName,
    unlockUrl: URL,
    transport: {
      async post(url, request) {
        ordinaryCalls.push({ url, request });
        const outcome = await ordinaryCore.endpoint.handleDocument(
          JSON.stringify(request),
          w.registration,
          { principal: { kind: "login", id: "reader" } },
        );
        return { ...outcome.response, contentType: "application/json" };
      },
    },
  });
  const answer = await ordinary.unlock(["body"]);
  assert.equal(answer.status, 200);
  assert.equal(await opened(ordinary), "first article text");
  assert.equal(ordinaryCalls.length, 1);
  assert.equal(JSON.stringify(ordinaryCalls[0]).includes(REFERENCE), false);
  assert.equal(w.calls.length, 1, "the failed grant was not replayed");
});
