// Inputs describe one resource. Workload generation happens before role timing.
export const groupNames = (count) =>
  Array.from({ length: count }, (_, i) => `group${String(i).padStart(4, "0")}`);

export const groupDefaults = Object.freeze({
  publisher: {
    origin: "https://news.example",
    resourceId: "story1",
    data: {},
    at: "2026-10-14T12:20:00.000Z",
    groups: 2,
    groupVocabulary: 2,
    periodGeometry: { chainsPerDay: 2, periodMinutes: 60 },
    sourceWindows: 2,
    itemPeriods: 1,
    variant: "ordinary",
  },
  issuer: { horizon: 6 },
  client: { initialCache: false, routeProbes: true, observeCache: true },
});

export function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object`);
}

export function known(value, names, label) {
  record(value, label);
  for (const name of Object.keys(value))
    if (!names.includes(name)) throw new Error(`unknown ${label} option ${name}`);
}

function positive(value, label, max = 1000) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max)
    throw new Error(`${label} must be a positive integer at most ${max}`);
}

export function resolveGroups(
  overrides = {},
  { compact = false, chainMemberCapacity = false } = {},
) {
  known(overrides, ["publisher", "issuer", "client"], "input");
  const p = overrides.publisher === undefined ? {} : overrides.publisher;
  const i = overrides.issuer === undefined ? {} : overrides.issuer;
  const c = overrides.client === undefined ? {} : overrides.client;
  known(
    p,
    [
      ...Object.keys(groupDefaults.publisher),
      "items",
      ...(chainMemberCapacity ? ["maxChainMembersPerMessage"] : []),
    ],
    "publisher",
  );
  known(i, ["horizon", "authorizedGroups"], "issuer");
  known(c, ["initialCache", "routeProbes", "observeCache"], "client");
  const publisher = {
    ...structuredClone(groupDefaults.publisher),
    ...(chainMemberCapacity ? { maxChainMembersPerMessage: 16 } : {}),
    ...p,
  };
  if (chainMemberCapacity)
    positive(
      publisher.maxChainMembersPerMessage,
      "publisher.maxChainMembersPerMessage",
      Number.MAX_SAFE_INTEGER,
    );
  if (p.groups !== undefined && p.groupVocabulary === undefined)
    publisher.groupVocabulary = Math.max(p.groups, groupDefaults.publisher.groupVocabulary);
  positive(publisher.groups, "publisher.groups");
  positive(publisher.groupVocabulary, "publisher.groupVocabulary");
  if (publisher.groups > publisher.groupVocabulary)
    throw new Error("publisher.groups exceeds groupVocabulary");
  positive(publisher.sourceWindows, "publisher.sourceWindows", 2);
  positive(publisher.itemPeriods, "publisher.itemPeriods", 48);
  known(publisher.periodGeometry, ["chainsPerDay", "periodMinutes"], "periodGeometry");
  if (
    typeof publisher.at !== "string" ||
    !publisher.at.includes("T") ||
    !Number.isFinite(Date.parse(publisher.at))
  )
    throw new Error("publisher.at is an ISO instant");
  publisher.at = new Date(publisher.at).toISOString();
  if (!["ordinary", ...(compact ? ["compact-ecdh"] : [])].includes(publisher.variant))
    throw new Error("unsupported publisher.variant for this scenario");
  const vocabulary = groupNames(publisher.groupVocabulary);
  const generated = [
    {
      name: "bodytext",
      value: "<p>The council voted 7–2 to rezone the harbour.</p>",
      contentType: "text/html",
      groups: vocabulary.slice(0, publisher.groups),
    },
  ];
  const items = p.items === undefined ? generated : p.items;
  if (!Array.isArray(items) || items.length === 0)
    throw new Error("publisher.items is a nonempty list");
  publisher.items = items.map((item) => {
    known(item, ["name", "value", "contentType", "groups"], "item");
    if (typeof item.name !== "string" || typeof item.value !== "string")
      throw new Error("items need a name and saved plaintext string value");
    const groups = item.groups === undefined ? vocabulary.slice(0, publisher.groups) : item.groups;
    if (
      !Array.isArray(groups) ||
      groups.length === 0 ||
      new Set(groups).size !== groups.length ||
      groups.some((g) => !vocabulary.includes(g))
    )
      throw new Error("item.groups must name distinct members of the generated groupVocabulary");
    return {
      name: item.name,
      value: item.value,
      contentType: item.contentType === undefined ? "text/plain" : item.contentType,
      groups: [...groups],
    };
  });
  if (new Set(publisher.items.map((item) => item.name)).size !== publisher.items.length)
    throw new Error("item names must be distinct");
  const issuer = { ...groupDefaults.issuer, ...i };
  if (!Number.isSafeInteger(issuer.horizon) || issuer.horizon < 0 || issuer.horizon > 47)
    throw new Error("issuer.horizon is a future-period offset from 0 through 47 (inclusive)");
  issuer.authorizedGroups =
    i.authorizedGroups === undefined
      ? [...new Set(publisher.items.flatMap((item) => item.groups))]
      : i.authorizedGroups;
  if (
    !Array.isArray(issuer.authorizedGroups) ||
    issuer.authorizedGroups.some((g) => !vocabulary.includes(g))
  )
    throw new Error("issuer.authorizedGroups must use the publisher vocabulary");
  const client = { ...groupDefaults.client, ...c };
  if (
    typeof client.initialCache !== "boolean" ||
    typeof client.routeProbes !== "boolean" ||
    typeof client.observeCache !== "boolean"
  )
    throw new Error("client.initialCache, routeProbes and observeCache are booleans");
  return structuredClone({ publisher, issuer, client });
}
