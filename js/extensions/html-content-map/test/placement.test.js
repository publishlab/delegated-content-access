// @ts-check
//
// Placement and the report, docs/spec-proposal--html-content-map.md Sections 4.3, 6.1,
// 6.3 and 6.4, over the server-side tree port. The key client here is a stub
// that answers each item with fixed octets or a fixed state, so these cases
// isolate what the run does with opened items: `fill` as HTML in the target's
// context or as one text node, `remove`, the DOMTokenList `remove` steps,
// partial entitlement, retained carriers and the report. Key acquisition and the
// item states it produces are `item-states.test.js`.

import test, { describe } from "node:test";
import assert from "node:assert/strict";

import { parseLockedDocument } from "../adapter-client/parse5Tree.js";
import { runContentMap, createContentMapSession } from "../core-client/contentMapRun.js";
import { decodeMapItemText } from "../core-client/mapItems.js";
import { classValueWithout, orderedTokenSet } from "../core-shared--client-publisher/treePort.js";
import { utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";

/**
 * A stub of the base client pieces: `opened` names each item's octets, and an
 * item absent from it resolves no key and the issuer omits it. The captured
 * view of every item reports `contentTypeOf(name)`, which the delivery stub
 * the map admits from reports too.
 *
 * @param {Record<string, Uint8Array>} opened
 * @param {(contentName: string) => string} [contentTypeOf]
 */
function stubClient(opened, contentTypeOf = () => "text/plain") {
  let unlocks = 0;
  const client = {
    dcaData: {
      contentItemFor: (/** @type {string} */ contentName) => ({
        contentName,
        contentType: contentTypeOf(contentName),
        contentEncodings: [],
        nonce: "",
        contentAad: new Uint8Array(0),
      }),
      accessGroupsFor: () => [],
    },
    reader: { extract: () => "QUJD" },
    resolver: {
      resolveDetailed: async (/** @type {any} */ _d, /** @type {string[]} */ names) => ({
        covered: names.filter((name) => Object.hasOwn(opened, name)),
        missing: names.filter((name) => !Object.hasOwn(opened, name)),
      }),
      contentKeyWithOriginFor: async () => ({ key: new Uint8Array(16) }),
    },
    opener: {
      open: async (/** @type {{ item: { contentName: string } }} */ call) =>
        opened[call.item.contentName],
    },
    unlock: async () => {
      unlocks += 1;
      return { status: 200, body: {}, application: { accepted: 0, errors: [], issues: [] } };
    },
  };
  return { client, unlocks: () => unlocks };
}

/**
 * Run the map on a page and return the serialized result.
 *
 * @param {string} body
 * @param {any} map
 * @param {Record<string, string|Uint8Array>} items
 */
async function place(body, map, items) {
  const wireMap = { version: map.version, rules: map.rules };
  const html = `<!DOCTYPE html><html><head></head><body class="page">${body}<script type="application/json" class="dca-data">${JSON.stringify({ contentMap: wireMap })}</script></body></html>`;
  const tree = parseLockedDocument(html);
  /** @type {Record<string, Uint8Array>} */
  const octets = {};
  for (const [name, value] of Object.entries(items)) {
    octets[name] = typeof value === "string" ? utf8Encode(value) : value;
  }
  const { client } = stubClient(octets, (name) => map.contentTypes[name]);
  const result = await runContentMap({
    tree,
    delivery: {
      declares: () => true,
      carriesCiphertext: () => true,
      contentType: (name) => map.contentTypes[name],
    },
    keyClient: () => /** @type {any} */ (client),
  });
  const serialized = tree.serialize();
  const bodyHtml = /** @type {RegExpExecArray} */ (
    /<body[^>]*>([\s\S]*)<\/body>/.exec(serialized)
  )[1];
  return {
    result,
    serialized,
    body: bodyHtml.replace(
      /<script type="application\/json" class="dca-data">[\s\S]*?<\/script>/g,
      "",
    ),
  };
}

describe("Section 6.3: operations", () => {
  test("fill parses text/html in the target's context and replaces every child", async () => {
    const map = {
      version: "1",
      contentTypes: { a: "text/html" },
      rules: [
        { item: "a", op: "fill", target: "#list" },
        { item: "a", op: "fill", target: "#div" },
      ],
    };
    const { body, result } = await place(
      '<ul id="list"><li>old</li></ul><div id="div">old</div>',
      map,
      { a: "<li>one</li><td>cell</td><script>never()</script>" },
    );
    assert.equal(result.report.outcome, "complete");
    // In a ul the li stays an element; a td outside a table is dropped with
    // its tag and keeps its text; a script is inserted as an element.
    assert.equal(
      body,
      '<ul id="list"><li>one</li>cell<script>never()</script></ul><div id="div"><li>one</li>cell<script>never()</script></div>',
    );
  });

  test("fill with text/plain appends one text node; an empty string leaves no children", async () => {
    const map = {
      version: "1",
      contentTypes: { t: "text/plain", e: "text/plain" },
      rules: [
        { item: "t", op: "fill", target: "#t" },
        { item: "e", op: "fill", target: "#e" },
      ],
    };
    const { body } = await place('<p id="t"><b>old</b></p><p id="e">old</p>', map, {
      t: "<b>not markup</b> & more",
      e: "",
    });
    assert.equal(body, '<p id="t">&lt;b&gt;not markup&lt;/b&gt; &amp; more</p><p id="e"></p>');
  });

  test("remove drops the target and its subtree; removeClass keeps the other tokens as an ordered set", async () => {
    const map = {
      version: "1",
      contentTypes: { a: "text/plain" },
      rules: [
        { item: "a", op: "fill", target: "#slot" },
        { item: "a", op: "remove", target: ".prompt" },
        { item: "a", op: "removeClass", target: "#slot", class: "locked" },
        { item: "a", op: "removeClass", target: "body", class: "page" },
      ],
    };
    const { body, serialized } = await place(
      '<div class="prompt"><p>Subscribe</p></div><div id="slot" class=" keep\tlocked keep  other ">x</div>',
      map,
      { a: "open" },
    );
    assert.equal(body, '<div id="slot" class="keep other">open</div>');
    assert.match(serialized, /<body class="">/, "an emptied class attribute stays, empty");
    assert.equal(classValueWithout("a b  a c", "b"), "a c");
    assert.deepEqual(orderedTokenSet("\fa\nb a\r"), ["a", "b"]);
  });

  test("the run preserves the embedded map and base carriers", async () => {
    const map = {
      version: "1",
      contentTypes: { a: "text/plain" },
      rules: [{ item: "a", op: "fill", target: "#slot" }],
    };
    const { serialized } = await place(
      '<div id="slot"></div><script type="application/json" class="dca-sealed-content">{}</script>',
      map,
      { a: "x" },
    );
    assert.equal(serialized.includes("dca-content-map"), false);
    assert.equal(serialized.includes('class="dca-data"'), true);
  });
});

describe("Section 6.2 and 6.4: partial entitlement and the report", () => {
  const map = {
    version: "1",
    contentTypes: { body: "text/html", box: "text/html" },
    rules: [
      { item: "body", op: "fill", target: "#body" },
      { item: "body", op: "removeClass", target: "#body", class: "locked" },
      { item: "body", op: "remove", target: ".prompt" },
      { item: "box", op: "fill", target: "#box" },
    ],
  };
  const page =
    '<div class="prompt">Subscribe</div><div id="body" class="locked">teaser</div><div id="box"></div>';

  test("an item in another state changes nothing: teaser, gate and lock class stay", async () => {
    const { body, result } = await place(page, map, { box: "<b>facts</b>" });
    assert.deepEqual(result.report, {
      outcome: "partial",
      items: { body: "locked", box: "opened" },
    });
    assert.equal(
      body,
      '<div class="prompt">Subscribe</div><div id="body" class="locked">teaser</div><div id="box"><b>facts</b></div>',
    );
    assert.equal(result.reconstructed, true);
    assert.deepEqual(
      result.targets.map((target) => target.path),
      [
        [1, 1],
        [1, 1],
        [1, 0],
        [1, 2],
      ],
      "each rule names its target by element-child indexes from the document element",
    );
  });

  test("every item opened is complete", async () => {
    const { result } = await place(page, map, { body: "<p>all</p>", box: "<b>facts</b>" });
    assert.deepEqual(result.report, {
      outcome: "complete",
      items: { body: "opened", box: "opened" },
    });
  });

  test("octets that are not UTF-8, or that begin with a byte order mark, are an item failure", async () => {
    const bom = Uint8Array.from([0xef, 0xbb, 0xbf, 0x61]);
    const broken = Uint8Array.from([0x61, 0xc3, 0x28]);
    assert.equal(decodeMapItemText(bom), null);
    assert.equal(decodeMapItemText(broken), null);
    assert.equal(decodeMapItemText(utf8Encode("é…")), "é…");
    const { result, body } = await place(page, map, { body: bom, box: broken });
    assert.deepEqual(result.report, {
      outcome: "failed",
      failure: "item_failed",
      items: { body: "failed", box: "failed" },
    });
    assert.equal(
      body,
      '<div class="prompt">Subscribe</div><div id="body" class="locked">teaser</div><div id="box"></div>',
      "a failed item leaves its targets locked",
    );
  });

  test("an item whose captured type differs from the type the map admitted is an item failure", async () => {
    // The map admits each item's type before the key is awaited; the opener
    // authenticates the type it captures after. The record changed between
    // the two reads, so the text is placed as neither type.
    const carrier = JSON.stringify({ contentMap: { version: map.version, rules: map.rules } });
    const tree = parseLockedDocument(
      `<!DOCTYPE html><html><head></head><body class="page">${page}` +
        `<script type="application/json" class="dca-data">${carrier}</script></body></html>`,
    );
    const { client } = stubClient(
      { body: utf8Encode("<p>all</p>"), box: utf8Encode("<b>facts</b>") },
      (name) => (name === "body" ? "text/plain" : map.contentTypes[name]),
    );
    const result = await runContentMap({
      tree,
      delivery: {
        declares: () => true,
        carriesCiphertext: () => true,
        contentType: (name) => map.contentTypes[name],
      },
      keyClient: () => /** @type {any} */ (client),
    });
    assert.equal(map.contentTypes.body, "text/html");
    assert.deepEqual(result.report, {
      outcome: "failed",
      failure: "item_failed",
      items: { body: "failed", box: "opened" },
    });
    assert.match(tree.serialize(), /<div id="body" class="locked">teaser<\/div>/);
  });

  test("a fresh client cannot replay completed gate rules on reconstructed output", async () => {
    const { serialized } = await place(page, map, { body: "<p>all</p>", box: "<b>facts</b>" });
    const again = await runContentMap({
      tree: parseLockedDocument(serialized),
      delivery: {
        declares: () => true,
        carriesCiphertext: () => true,
        contentType: (name) => map.contentTypes[name],
      },
      keyClient: () => {
        throw new Error("no key work for a delivery without a map");
      },
    });
    assert.deepEqual(again.report, { outcome: "failed", failure: "map_target_count" });
  });
});

/** A fresh opt-in session with two independent items and a gate preceding fills. */
function sessionFixture() {
  const rules = [
    { item: "a", op: "removeClass", target: "#a", class: "locked" },
    { item: "a", op: "fill", target: "#a" },
    { item: "a", op: "fill", target: "#copy" },
    { item: "b", op: "fill", target: "#b" },
  ];
  const html = `<!DOCTYPE html><html><head></head><body><section><div id="a" class="locked">teaser</div><div id="copy">copy teaser</div><div id="b">box teaser</div></section><script class="dca-data" type="application/json">${JSON.stringify({ contentMap: { version: "1", rules } })}</script></body></html>`;
  const tree = parseLockedDocument(html);
  /** @type {Record<string, Uint8Array>} */
  const bytes = { a: utf8Encode("article") };
  const { client, unlocks } = stubClient(bytes);
  const options = {
    tree,
    delivery: {
      declares: () => true,
      carriesCiphertext: () => true,
      contentType: () => "text/plain",
    },
    keyClient: () => /** @type {any} */ (client),
  };
  return { tree, bytes, client, options, unlocks };
}

describe("explicit reconstruction sessions", () => {
  test("retry opens only locked items and never replays completed placements", async () => {
    const fixture = sessionFixture();
    const session = createContentMapSession(fixture.options);
    assert.equal((await session.run()).report.outcome, "partial");
    const snapshot = session.snapshot();
    assert.ok(snapshot.html.includes('id="a" class="">article</div>'));
    fixture.bytes.a = utf8Encode("must not replay");
    fixture.bytes.b = utf8Encode("box");
    assert.deepEqual((await session.run()).report, {
      outcome: "complete",
      items: { a: "opened", b: "opened" },
    });
    assert.ok(!session.snapshot().html.includes("must not replay"));
    const complete = session.snapshot().html;
    await session.run();
    assert.equal(session.snapshot().html, complete);
    assert.equal(fixture.unlocks(), 1);
    const section = fixture.tree.children(
      fixture.tree.children(fixture.tree.documentElement())[1],
    )[0];
    fixture.tree.fillText(fixture.tree.children(section)[2], "external edit");
    assert.throws(
      () => session.snapshot(),
      { code: "map_target_stale" },
      "a completed session refuses a snapshot of a changed document",
    );
  });

  test("a pending retry excludes overlapping attempts and snapshots, then places its item once", async () => {
    const fixture = sessionFixture();
    let acquisitions = 0;
    let commits = 0;
    const prepare = fixture.tree.prepareFill;
    fixture.tree.prepareFill = (...args) => {
      const fill = prepare(...args);
      return {
        ...fill,
        commit() {
          commits++;
          fill.commit();
        },
      };
    };
    /** @type {(value: any) => void} */
    let release = () => {};
    const pending = new Promise((resolve) => {
      release = resolve;
    });
    const session = createContentMapSession({
      ...fixture.options,
      keyClient: () => {
        acquisitions++;
        if (acquisitions === 1) return fixture.client;
        if (acquisitions === 2) return pending;
        throw new Error("an overlapping attempt reached acquisition");
      },
    });
    assert.equal((await session.run()).report.outcome, "partial");
    assert.equal(commits, 2);
    fixture.bytes.b = utf8Encode("box");
    const running = session.run();
    try {
      await assert.rejects(() => session.run(), { code: "bad_config" });
      assert.throws(() => session.snapshot(), { code: "bad_config" });
      assert.equal(acquisitions, 2);
      assert.equal(commits, 2, "pending acquisition has no placement effects");
    } finally {
      release(fixture.client);
      await running;
    }
    assert.equal((await running).report.outcome, "complete");
    assert.equal(commits, 3, "only the newly opened item is placed");
    const completed = session.snapshot().html;
    assert.ok(completed.includes('id="b">box</div>'));
    await session.run();
    assert.equal(session.snapshot().html, completed);
    assert.equal(acquisitions, 2);
    assert.equal(commits, 3);
  });

  test("mutation during acquisition refuses placement and later snapshots", async () => {
    const fixture = sessionFixture();
    /** @type {(value: any) => void} */
    let release = () => {};
    const pending = new Promise((resolve) => {
      release = resolve;
    });
    const session = createContentMapSession({ ...fixture.options, keyClient: () => pending });
    const running = session.run();
    const root = fixture.tree.documentElement();
    const section = fixture.tree.children(fixture.tree.children(root)[1])[0];
    fixture.tree.fillText(fixture.tree.children(section)[0], "external edit");
    release(fixture.client);
    const result = await running;
    assert.equal(/** @type {any} */ (result.report).failure, "map_target_stale");
    assert.ok(fixture.tree.serialize().includes('class="locked">external edit'));
    assert.throws(
      () => session.snapshot(),
      (/** @type {any} */ error) => error.code === "map_target_stale",
    );
  });

  test("replacement by identical markup is stale even when serialization matches", async () => {
    const fixture = sessionFixture();
    const session = createContentMapSession(fixture.options);
    const root = fixture.tree.documentElement();
    const section = fixture.tree.children(fixture.tree.children(root)[1])[0];
    fixture.tree.fillHtml(
      section,
      '<div id="a" class="locked">teaser</div><div id="copy">copy teaser</div><div id="b">box teaser</div>',
    );
    const result = await session.run();
    assert.equal(/** @type {any} */ (result.report).failure, "map_target_stale");
    assert.equal(fixture.unlocks(), 0);
  });

  test("preparing every fill precedes lock removal and a refused sink changes no target", async () => {
    const fixture = sessionFixture();
    const before = fixture.tree.serialize();
    const prepare = fixture.tree.prepareFill;
    let fills = 0;
    fixture.tree.prepareFill = (...args) => {
      fills += 1;
      if (fills === 2) throw new TypeError("host sink refused");
      return prepare(...args);
    };
    const result = await createContentMapSession(fixture.options).run();
    assert.equal(result.report.outcome, "failed");
    assert.equal(result.report.failure, "map_placement_refused");
    if (result.report.items) assert.equal(result.report.items.a, "failed");
    assert.equal(fixture.tree.serialize(), before);
  });

  test("a failed second fill rolls back the first and keeps the gate locked", async () => {
    const fixture = sessionFixture();
    const before = fixture.tree.serialize();
    const prepare = fixture.tree.prepareFill;
    let fills = 0;
    fixture.tree.prepareFill = (...args) => {
      const prepared = prepare(...args);
      fills += 1;
      if (fills === 2)
        return {
          ...prepared,
          commit: () => {
            throw new TypeError("commit refused");
          },
        };
      return prepared;
    };
    const result = await createContentMapSession(fixture.options).run();
    assert.equal(/** @type {any} */ (result.report).failure, "map_placement_refused");
    assert.equal(fixture.tree.serialize(), before);
  });

  test("a thrown acquisition ends the session with no placement or implicit retry", async () => {
    const fixture = sessionFixture();
    const before = fixture.tree.serialize();
    let calls = 0;
    const session = createContentMapSession({
      ...fixture.options,
      keyClient: () => {
        calls += 1;
        throw new Error("offline");
      },
    });
    const failed = await session.run();
    assert.equal(failed.report.failure, "key_acquisition_failed");
    assert.equal(failed.reconstructed, false);
    assert.deepEqual(failed.targets, []);
    await session.run();
    assert.equal(calls, 1);
    assert.equal(fixture.tree.serialize(), before);
  });

  test("integrator configuration errors throw instead of becoming map reports", async () => {
    const fixture = sessionFixture();
    assert.throws(() => createContentMapSession({ ...fixture.options, limits: { rules: 0 } }), {
      code: "bad_config",
    });
    const session = createContentMapSession({
      ...fixture.options,
      keyClient: () => {
        throw dcaError("bad_config", "the integrator's key client is misconfigured");
      },
    });
    await assert.rejects(() => session.run(), { code: "bad_config" });
  });
});

test("returned reports and snapshots cannot change session retry state", async () => {
  const fixture = sessionFixture();
  const session = createContentMapSession(fixture.options);
  const first = await session.run();
  /** @type {any} */ (first.report).outcome = "complete";
  /** @type {any} */ (first.report).items.b = "opened";
  const snapshot = session.snapshot();
  /** @type {any} */ (snapshot.report).items.a = "failed";
  fixture.bytes.b = utf8Encode("box");
  assert.deepEqual((await session.run()).report, {
    outcome: "complete",
    items: { a: "opened", b: "opened" },
  });
});

test("a synchronous fill callback replacing another target refuses before gates", async () => {
  const fixture = sessionFixture();
  const prepare = fixture.tree.prepareFill;
  let first = true;
  fixture.tree.prepareFill = (...args) => {
    const prepared = prepare(...args);
    if (!first) return prepared;
    first = false;
    return {
      ...prepared,
      commit() {
        prepared.commit();
        const root = fixture.tree.documentElement();
        const section = fixture.tree.children(fixture.tree.children(root)[1])[0];
        fixture.tree.fillHtml(
          section,
          '<div id="a" class="locked">replacement</div><div id="copy">replacement</div><div id="b">replacement</div>',
        );
      },
    };
  };
  const session = createContentMapSession(fixture.options);
  const result = await session.run();
  assert.equal(/** @type {any} */ (result.report).failure, "map_target_stale");
  assert.ok(fixture.tree.serialize().includes('class="locked"'));
  assert.throws(
    () => session.snapshot(),
    (/** @type {any} */ error) => error.code === "map_target_stale",
  );
});

test("rollback refusal never escapes as a successful or unreported reconstruction", async () => {
  const fixture = sessionFixture();
  fixture.tree.prepareFill = () => ({
    matches: () => false,
    commit: () => {
      throw new Error("commit");
    },
    rollback: () => {
      throw new Error("rollback");
    },
  });
  const session = createContentMapSession(fixture.options);
  const result = await session.run();
  assert.equal(/** @type {any} */ (result.report).failure, "map_placement_refused");
  assert.throws(
    () => session.snapshot(),
    (/** @type {any} */ error) => error.code === "map_placement_refused",
  );
});

test("synchronous fill side effects cannot change unrelated text or attributes", async () => {
  for (const kind of ["text", "attribute", "fill"]) {
    const fixture = sessionFixture();
    const prepare = fixture.tree.prepareFill;
    const section = fixture.tree.children(
      fixture.tree.children(fixture.tree.documentElement())[1],
    )[0];
    const b = fixture.tree.children(section)[2];
    fixture.tree.prepareFill = (...args) => {
      const prepared = prepare(...args);
      return {
        ...prepared,
        commit() {
          prepared.commit();
          if (kind === "text") fixture.tree.fillText(b, "collateral text");
          else if (kind === "attribute")
            b.attrs.push({ name: "data-changed", value: "collateral" });
          else fixture.tree.fillText(args[0], "content other than prepared fill");
        },
      };
    };
    const session = createContentMapSession(fixture.options);
    assert.equal((await session.run()).report.failure, "map_target_stale", kind);
    assert.ok(fixture.tree.serialize().includes('class="locked"'));
    assert.throws(
      () => session.snapshot(),
      (error) => error.code === "map_target_stale",
    );
  }
});

test("gate side effects cannot change unrelated text", async () => {
  const fixture = sessionFixture();
  const removeClass = fixture.tree.removeClass;
  const section = fixture.tree.children(
    fixture.tree.children(fixture.tree.documentElement())[1],
  )[0];
  const b = fixture.tree.children(section)[2];
  fixture.tree.removeClass = (...args) => {
    removeClass(...args);
    fixture.tree.fillText(b, "collateral");
  };
  const session = createContentMapSession(fixture.options);
  const { report } = await session.run();
  assert.equal(report.outcome, "failed");
  assert.equal(report.failure, "map_target_stale");
  if (report.items) assert.equal(report.items.a, "failed");
  assert.throws(
    () => session.snapshot(),
    (error) => error.code === "map_target_stale",
  );
});

test("retirement or lost eligibility before or across acquisition stops key work and placement", async () => {
  for (const retire of ["dispose", "eligibility", "dispose before run", "throwing check"]) {
    const fixture = sessionFixture();
    const before = fixture.tree.serialize();
    let eligible = true;
    let acquisitions = 0;
    let release;
    const pending = new Promise((resolve) => {
      release = resolve;
    });
    const session = createContentMapSession({
      ...fixture.options,
      isEligible: () => {
        if (retire === "throwing check") throw new Error("host check failed");
        return eligible;
      },
      keyClient: () => {
        acquisitions++;
        return pending;
      },
    });
    if (retire === "dispose before run") session.dispose();
    const running = session.run();
    if (retire === "dispose") session.dispose();
    else if (retire === "eligibility") eligible = false;
    release(fixture.client);
    assert.equal((await running).report.failure, "map_target_stale", retire);
    const started = retire === "dispose" || retire === "eligibility";
    assert.equal(
      acquisitions,
      started ? 1 : 0,
      `${retire}: key acquisition starts only while live`,
    );
    assert.equal(fixture.unlocks(), 0, `${retire}: no unlock after retirement`);
    assert.equal(fixture.tree.serialize(), before);
    assert.throws(
      () => session.snapshot(),
      (error) => error.code === "map_target_stale",
    );
  }
});

test("host eligibility is checked between synchronous fill effects and before gates", async () => {
  const fixture = sessionFixture();
  const before = fixture.tree.serialize();
  const prepare = fixture.tree.prepareFill;
  let eligible = true;
  fixture.tree.prepareFill = (...args) => {
    const prepared = prepare(...args);
    return {
      ...prepared,
      commit() {
        prepared.commit();
        eligible = false;
      },
    };
  };
  const session = createContentMapSession({ ...fixture.options, isEligible: () => eligible });
  assert.equal((await session.run()).report.failure, "map_target_stale");
  assert.equal(fixture.tree.serialize(), before);
});

test("a first fill that changes the next target stops before the next effect", async () => {
  const fixture = sessionFixture();
  const prepare = fixture.tree.prepareFill;
  const section = fixture.tree.children(
    fixture.tree.children(fixture.tree.documentElement())[1],
  )[0];
  const nextTarget = fixture.tree.children(section)[1];
  let commits = 0;
  fixture.tree.prepareFill = (...args) => {
    const prepared = prepare(...args);
    return {
      ...prepared,
      commit() {
        commits++;
        prepared.commit();
        fixture.tree.fillText(nextTarget, "collateral");
      },
    };
  };
  const result = await createContentMapSession(fixture.options).run();
  assert.equal(result.report.failure, "map_target_stale");
  assert.equal(commits, 1, "the second fill is never attempted");
});

test("a first gate that changes the next target stops before the next gate", async () => {
  const map = {
    version: "1",
    rules: [
      { item: "a", op: "fill", target: "#a" },
      { item: "a", op: "remove", target: "#one" },
      { item: "a", op: "remove", target: "#two" },
    ],
  };
  const tree = parseLockedDocument(
    `<!doctype html><html><body><div id="a">teaser</div><aside id="one">one</aside><aside id="two">two</aside><script class="dca-data" type="application/json">${JSON.stringify({ contentMap: map })}</script></body></html>`,
  );
  const body = tree.children(tree.documentElement())[1];
  const second = tree.children(body)[2];
  const remove = tree.remove;
  let removes = 0;
  tree.remove = (element) => {
    removes++;
    remove(element);
    tree.fillText(second, "collateral");
  };
  const { client } = stubClient({ a: utf8Encode("body") });
  const session = createContentMapSession({
    tree,
    delivery: {
      declares: () => true,
      carriesCiphertext: () => true,
      contentType: () => "text/plain",
    },
    keyClient: () => client,
  });
  assert.equal((await session.run()).report.failure, "map_target_stale");
  assert.equal(removes, 1, "the second gate is never attempted");
});
