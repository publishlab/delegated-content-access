import { writeJsonDelivery } from "../../../../adapter-publisher/writeJsonDelivery.js";
import { JsonDeliveryReader } from "../../../../adapter-client/JsonDeliveryReader.js";
import { createDeliveryClient } from "../../../../integration-client/createDeliveryClient.js";

export const ISSUER = "issuer";
export const UNLOCK = "https://issuer.example/unlock";
export const FIXTURE_SECRET = Uint8Array.from({ length: 32 }, (_, i) => i);
export const random = { bytes: (n) => crypto.getRandomValues(new Uint8Array(n)) };

export async function keys() {
  const signing = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const opening = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  return { signing, opening };
}

export function registrationFor({ signing, opening }, compact = false) {
  return {
    kid: "p1",
    publicKey: signing.publicKey,
    openingKeys: {
      get: (name, keyId) =>
        name === ISSUER && keyId === "k1"
          ? {
              algorithm: "ecdh-p256",
              privateKey: opening.privateKey,
              ...(compact
                ? { publicKey: opening.publicKey, envelopes: ["ecdh-p256", "compact-ecdh"] }
                : {}),
            }
          : undefined,
    },
  };
}

export function stringStore() {
  const values = new Map();
  return {
    async get(k) {
      return values.get(k) ?? null;
    },
    async set(k, v) {
      if (typeof k !== "string" || typeof v !== "string") throw new Error("string store only");
      values.set(k, v);
    },
    async keys() {
      return [...values.keys()];
    },
    async remove(k) {
      values.delete(k);
    },
    summary() {
      const keyBytes = [...values.keys()].reduce((n, v) => n + Buffer.byteLength(v), 0);
      const valueBytes = [...values.values()].reduce((n, v) => n + Buffer.byteLength(v), 0);
      return { entries: values.size, keyBytes, valueBytes, totalBytes: keyBytes + valueBytes };
    },
  };
}

// Account the known delivery shape at its authored byte boundaries. This is
// deliberately finite: item records, their seal and connector records, and
// whole issuer and ciphertext members; no recursive discovery of arbitrary
// protocol or extension structures. A record label carries its array index
// before its name, because the wire may repeat a coordinate as candidates.
export function deliveryPartitions(document) {
  const parts = {};
  function members(value, label, emit) {
    parts[`framing:${label}:open`] = "{";
    Object.entries(value).forEach(([key, member], index) => {
      parts[`framing:${label}:${JSON.stringify(key)}`] =
        `${index ? "," : ""}${JSON.stringify(key)}:`;
      emit(key, member);
    });
    parts[`framing:${label}:close`] = "}";
  }
  function records(value, label, nameField, emit) {
    parts[`framing:${label}:open`] = "[";
    value.forEach((record, index) => {
      if (index) parts[`framing:${label}:${index}`] = ",";
      emit(`${label}:${index}:${JSON.stringify(record[nameField])}`, record);
    });
    parts[`framing:${label}:close`] = "]";
  }
  members(document, "document", (key, value) => {
    if (key === "contentData") {
      records(value, "items", "contentName", (label, item) => {
        members(item, label, (field, metadata) => {
          if (field === "keys" || field === "connectors") {
            const [kind, nameField] =
              field === "keys" ? ["seals", "accessGroup"] : [field, "group"];
            records(metadata, `${label}:${kind}`, nameField, (recordLabel, authored) => {
              parts[recordLabel] = JSON.stringify(authored);
            });
          } else parts[`${label}:metadata:${JSON.stringify(field)}`] = JSON.stringify(metadata);
        });
      });
    } else {
      const name = {
        issuerData: "sources",
        resourceJWT: "signedToken",
        sealedContent: "ciphertext",
      }[key];
      parts[name ?? `metadata:${JSON.stringify(key)}`] = JSON.stringify(value);
    }
  });
  return parts;
}

export function publishCapture(render, origin, observe) {
  const bytes = writeJsonDelivery(render);
  const text = new TextDecoder().decode(bytes);
  const document = JSON.parse(text);
  observe.capture("delivery", document, { text, partitions: deliveryPartitions(document) });
  observe.capture("dcaData", render.dcaData, { partitions: deliveryPartitions(render.dcaData) });
  observe.capture("content", render.sealedContent);
  observe.count(
    "ciphertextBytes",
    Object.values(render.sealedContent).reduce(
      (n, value) => n + Buffer.from(value, "base64url").byteLength,
      0,
    ),
  );
  const read = new JsonDeliveryReader(bytes, { publisherOrigin: origin });
  observe.check(
    "delivery-round-trip",
    JSON.stringify(read.dcaData) === JSON.stringify(render.dcaData) &&
      Object.entries(render.sealedContent).every(
        ([name, ciphertext]) => read.extract(name) === ciphertext,
      ),
  );
  return { bytes, reader: () => new JsonDeliveryReader(bytes, { publisherOrigin: origin }) };
}

export function assembledClient({
  published,
  endpoint,
  registration,
  at,
  options,
  observe,
  label = "",
  silent = false,
}) {
  const transport = {
    async post(_url, request) {
      const text = JSON.stringify(request);
      if (!silent) {
        observe.capture(`${label}request`, JSON.parse(text), { text });
        observe.count(label ? `${label}unlock` : "unlock");
      } else observe.count("initialCacheSetupUnlock");
      const call = () => endpoint.handleDocument(text, registration, {}, Date.parse(at));
      const answer = silent
        ? await call()
        : await observe.time(`${label}issuer`, call, { nested: true });
      const responseText = JSON.stringify(answer.response.body);
      if (!silent)
        observe.capture(`${label}response`, JSON.parse(responseText), {
          text: responseText,
          status: answer.response.status,
        });
      return {
        status: answer.response.status,
        contentType: "application/json",
        body: JSON.parse(responseText),
      };
    },
  };
  return createDeliveryClient({
    reader: published.reader(),
    issuerName: ISSUER,
    unlockUrl: UNLOCK,
    transport,
    ...options,
  });
}

export async function verifyItems(client, items, permitted, observe, prefix = "item:") {
  for (const item of items) {
    let actual = null;
    let failure;
    try {
      actual = new TextDecoder().decode((await client.openLocal(item.name)).bytes);
    } catch (error) {
      failure = error.code ?? error.message;
    }
    const expected = permitted(item);
    observe.check(
      `${prefix}${item.name}`,
      expected ? actual === item.value : actual === null && failure === "no_key",
      {
        expected: expected ? "opens authored plaintext" : "refused",
        opened: actual !== null,
        ...(failure ? { code: failure } : {}),
      },
    );
  }
}

export async function cacheSnapshot(caches, store) {
  const summaries = {};
  for (const [name, cache] of Object.entries(caches)) {
    const entries = await cache.entries();
    summaries[name] = {
      entries: entries.length,
      coordinates: entries.map(({ familyName, t, kind }) => ({
        familyName,
        t,
        kind: kind ?? "period-key",
      })),
      chainKeys: entries.filter((e) => e.kind === "chain-key").length,
      periodKeys: entries.filter((e) => e.kind !== "chain-key").length,
    };
  }
  return {
    caches: summaries,
    storage: store.summary(),
    observation:
      "entries() after role calls; fixed case clock; fixture retains keys without time expiry; capacity eviction remains active",
  };
}

export function checkedEndpoint(endpoint, observe, coordinates, expected) {
  return {
    async handleDocument(...args) {
      const answer = await endpoint.handleDocument(...args);
      const actual = coordinates(answer.response.body).sort();
      observe.check(
        "returned-chain-coordinates",
        (expected.length === 0 ? intendedDenial(answer) : answer.response.status === 200) &&
          JSON.stringify(actual) === JSON.stringify([...expected].sort()),
        { expected, actual, status: answer.response.status },
      );
      return answer;
    },
  };
}

// A denial body holds its error code and nothing else. The exact member set
// catches a renamed key member: a check for the old `contentGroups` name kept
// passing after the issuer started writing `contentGroupKeys`.
function intendedDenial(answer) {
  const body = answer.response.body;
  return (
    answer.response.status === 401 &&
    body?.error === "denied" &&
    !Object.hasOwn(body, "keys") &&
    !Object.hasOwn(body, "contentGroupKeys") &&
    Object.keys(body).length === 1
  );
}

export async function runClientStage({
  input,
  observe,
  scope,
  published,
  endpoint,
  registration,
  makeClient,
  permitted,
  expectedChainCount,
}) {
  const { publisher: p, client: c } = input;
  const names = p.items.map((item) => item.name);
  observe.count("unlock", 0);
  const held = makeClient();
  if (scope === "publisher-issuer") {
    const client = assembledClient({
      published,
      endpoint,
      registration,
      at: p.at,
      options: held.options,
      observe,
    });
    const request = client.builder.build(client.dcaData, ISSUER, names).toObject();
    const text = JSON.stringify(request);
    observe.capture("request", JSON.parse(text), { text });
    observe.count("unlock");
    const answer = await observe.time("issuer", () =>
      endpoint.handleDocument(text, registration, {}, Date.parse(p.at)),
    );
    const responseText = JSON.stringify(answer.response.body);
    observe.capture("response", JSON.parse(responseText), {
      text: responseText,
      status: answer.response.status,
    });
    observe.check(
      "issuer-status",
      expectedChainCount === 0 ? intendedDenial(answer) : answer.response.status === 200,
      {
        status: answer.response.status,
        code: answer.code,
      },
    );
    return;
  }
  if (c.initialCache) {
    observe.count("initialCacheSetupUnlock", 0);
    const warm = assembledClient({
      published,
      endpoint,
      registration,
      at: p.at,
      options: held.options,
      observe,
      silent: true,
    });
    await observe.time("initial-cache-setup", () =>
      warm.unlockRoutes(names, [{ issuerName: ISSUER, unlockUrl: UNLOCK }]),
    );
  }
  const client = assembledClient({
    published,
    endpoint,
    registration,
    at: p.at,
    options: held.options,
    observe,
  });
  const unmeasured = {
    measured: false,
    reason: "client.observeCache is false; cache entries and durable storage were not observed",
  };
  observe.snapshot(
    "before",
    c.observeCache === false ? unmeasured : await cacheSnapshot(held.caches, held.store),
  );
  const result = await observe.time("client", () =>
    client.unlockRoutes(names, [{ issuerName: ISSUER, unlockUrl: UNLOCK }]),
  );
  observe.check("route-walk", result.failed.length === 0, result);
  await observe.time("opening", () => verifyItems(client, p.items, permitted, observe));
  const after =
    c.observeCache === false ? unmeasured : await cacheSnapshot(held.caches, held.store);
  observe.snapshot("after", after);
  if (c.observeCache !== false && expectedChainCount !== undefined)
    observe.check("retained-chain-keys", after.caches.chain.chainKeys === expectedChainCount, {
      expected: expectedChainCount,
      actual: after.caches.chain.chainKeys,
    });
}
