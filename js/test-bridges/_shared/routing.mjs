/** @param {string} path */
export function isSafeModulePath(path) {
  return (
    /^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.m?js$/.test(path) &&
    !path.split("/").includes(".") &&
    !path.split("/").includes("..")
  );
}

/**
 * Only implementation modules cross to a test target. Tests, test helpers
 * (`test-*` directories) and demo code are the driver's own and always load
 * locally. Importing a test in the adapter child could also register
 * node:test cases there and contaminate its framed stdout.
 *
 * @param {string} path
 */
export function isDriverOwnedModule(path) {
  return (
    path
      .split("/")
      .some((segment) => segment === "test" || segment === "demo" || segment.startsWith("test-")) ||
    /\.test\.(?:js|mjs|cjs)$/.test(path)
  );
}

/** @param {string} value */
export function isIdentifier(value) {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(value);
}

/** @param {unknown} value @param {readonly string[]} allowed */
function onlyMembers(value, allowed) {
  return Object.keys(/** @type {object} */ (value)).every((key) => allowed.includes(key));
}

/**
 * Validates a `describe` reply exactly: `identity` (optional record of
 * strings), `capabilities` and top-level `errorTypes`. An unknown or misplaced member is refused rather than silently dropped.
 *
 * @param {unknown} value
 */
export function validateDescription(value) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("describe reply is an object");
  if (!onlyMembers(value, ["identity", "capabilities", "errorTypes"]))
    throw new TypeError("describe reply has only identity, capabilities and errorTypes");
  const described =
    /** @type {{ identity?: unknown, capabilities?: unknown, errorTypes?: unknown }} */ (value);
  if (described.identity !== undefined) {
    const identity = described.identity;
    if (
      !identity ||
      typeof identity !== "object" ||
      Array.isArray(identity) ||
      !Object.values(identity).every((member) => typeof member === "string")
    )
      throw new TypeError("describe identity members are strings");
  }
  return Object.freeze({
    capabilities: validateCapabilities(described.capabilities),
    errorTypes: validateErrorTypes(described.errorTypes ?? []),
  });
}

/** @param {unknown} capabilities */
export function validateCapabilities(capabilities) {
  if (!capabilities || typeof capabilities !== "object")
    throw new TypeError("capabilities are an object");
  if (!onlyMembers(capabilities, ["valueTypes", "moduleDiscovery"]))
    throw new TypeError("capabilities have only valueTypes and moduleDiscovery");
  const valueTypes = /** @type {{ valueTypes?: unknown }} */ (capabilities).valueTypes ?? [];
  if (!Array.isArray(valueTypes) || !valueTypes.every((value) => typeof value === "string"))
    throw new TypeError("capability value types are strings");
  if (new Set(valueTypes).size !== valueTypes.length)
    throw new TypeError("capability value types are unique");
  if (/** @type {{ moduleDiscovery?: unknown }} */ (capabilities).moduleDiscovery !== true)
    throw new TypeError("capabilities support module discovery");
  return Object.freeze({
    valueTypes: Object.freeze([...valueTypes]),
    moduleDiscovery: /** @type {const} */ (true),
  });
}

/** @param {unknown} value */
export function validateModuleMembers(value) {
  if (
    !value ||
    typeof value !== "object" ||
    !Array.isArray(/** @type {{ members?: unknown }} */ (value).members)
  )
    throw new TypeError("module description has members");
  const members = /** @type {any[]} */ (/** @type {{ members: unknown[] }} */ (value).members);
  if (
    !members.every(
      (member) =>
        member &&
        typeof member === "object" &&
        typeof member.id === "string" &&
        member.id.length > 0 &&
        typeof member.sourceExport === "string" &&
        isIdentifier(member.sourceExport) &&
        (member.callShape === "sync" ||
          member.callShape === "async" ||
          member.callShape === "value"),
    )
  )
    throw new TypeError("module members have safe IDs, exports, and call shapes");
  if (new Set(members.map((member) => member.id)).size !== members.length)
    throw new TypeError("module member IDs are unique");
  if (new Set(members.map((member) => member.sourceExport)).size !== members.length)
    throw new TypeError("module member exports are unique");
  return Object.freeze(
    members.map((member) =>
      Object.freeze({
        id: member.id,
        sourceExport: member.sourceExport,
        callShape: member.callShape,
      }),
    ),
  );
}

/**
 * Validates the optional `classes` of a module description: each class the
 * test target claims, by an opaque ID and its reference export name, with the
 * instance members it claims and, when the test target can construct it, the
 * operation ID of its constructor. Member and constructor IDs are operation
 * IDs like any other, so they are unique beside the module's own member IDs.
 *
 * @param {unknown} value the module description
 * @param {readonly { id: string }[]} members the module's validated members
 * @returns {readonly { id: string, sourceExport: string, construct?: { id: string }, members: readonly { id: string, sourceMember: string, callShape: 'sync'|'async' }[] }[]}
 */
export function validateModuleClasses(value, members) {
  const described = /** @type {{ classes?: unknown }} */ (value);
  if (described.classes === undefined) return Object.freeze([]);
  const classes = described.classes;
  const valid = Array.isArray(classes) && classes.every(isModuleClass);
  if (!valid) throw new TypeError("module classes have safe IDs, exports and members");
  const list =
    /** @type {{ id: string, sourceExport: string, construct?: { id: string }, members: { id: string, sourceMember: string, callShape: 'sync'|'async' }[] }[]} */ (
      classes
    );
  const classIds = list.map((entry) => entry.id);
  if (new Set(classIds).size !== classIds.length)
    throw new TypeError("module class IDs are unique");
  const operationIds = [
    ...members.map((member) => member.id),
    ...list.flatMap((entry) => entry.members.map((member) => member.id)),
    ...list.flatMap((entry) => (entry.construct === undefined ? [] : [entry.construct.id])),
  ];
  if (new Set(operationIds).size !== operationIds.length)
    throw new TypeError("module member and class member IDs are unique");
  for (const entry of list) {
    const names = entry.members.map((member) => member.sourceMember);
    if (new Set(names).size !== names.length)
      throw new TypeError("module class member names are unique");
  }
  return Object.freeze(
    list.map((entry) =>
      Object.freeze({
        id: entry.id,
        sourceExport: entry.sourceExport,
        ...(entry.construct === undefined
          ? {}
          : { construct: Object.freeze({ id: entry.construct.id }) }),
        members: Object.freeze(
          entry.members.map((member) =>
            Object.freeze({
              id: member.id,
              sourceMember: member.sourceMember,
              callShape: member.callShape,
            }),
          ),
        ),
      }),
    ),
  );
}

/**
 * One claimed class: an opaque ID, the reference class export, its members
 * and an optional constructor operation `{ id }`.
 *
 * @param {unknown} value
 */
function isModuleClass(value) {
  if (value === null || typeof value !== "object") return false;
  const entry =
    /** @type {{ id?: unknown, sourceExport?: unknown, construct?: unknown, members?: unknown }} */ (
      value
    );
  const exact = onlyMembers(entry, ["id", "sourceExport", "construct", "members"]);
  const identified = typeof entry.id === "string" && entry.id.length > 0;
  const named = typeof entry.sourceExport === "string" && isIdentifier(entry.sourceExport);
  const members = Array.isArray(entry.members) && entry.members.every(isClassMember);
  const constructible = entry.construct === undefined || isConstructor(entry.construct);
  return exact && identified && named && members && constructible;
}

/**
 * The constructor operation of a claimed class: exactly an opaque ID.
 *
 * @param {unknown} value
 */
function isConstructor(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const entry = /** @type {{ id?: unknown }} */ (value);
  const exact = onlyMembers(entry, ["id"]);
  const identified = typeof entry.id === "string" && entry.id.length > 0;
  return exact && identified;
}

/**
 * One instance member of a claimed class: an opaque operation ID, the
 * reference member name and a callable shape.
 *
 * @param {unknown} value
 */
function isClassMember(value) {
  if (value === null || typeof value !== "object") return false;
  const member = /** @type {{ id?: unknown, sourceMember?: unknown, callShape?: unknown }} */ (
    value
  );
  const exact = onlyMembers(member, ["id", "sourceMember", "callShape"]);
  const identified = typeof member.id === "string" && member.id.length > 0;
  const named = typeof member.sourceMember === "string" && isIdentifier(member.sourceMember);
  const callable = member.callShape === "sync" || member.callShape === "async";
  return exact && identified && named && callable;
}

/** @param {unknown} value */
export function validateErrorTypes(value) {
  if (!Array.isArray(value)) throw new TypeError("bridge error types are a list");
  if (
    !value.every(
      (descriptor) =>
        descriptor &&
        typeof descriptor === "object" &&
        typeof descriptor.id === "string" &&
        descriptor.id.length > 0 &&
        typeof descriptor.sourceModule === "string" &&
        isSafeModulePath(descriptor.sourceModule) &&
        typeof descriptor.sourceExport === "string" &&
        isIdentifier(descriptor.sourceExport) &&
        Object.keys(descriptor).length === 3,
    )
  )
    throw new TypeError("bridge error types have safe IDs, modules, and exports");
  if (new Set(value.map((descriptor) => descriptor.id)).size !== value.length)
    throw new TypeError("bridge error type IDs are unique");
  return Object.freeze(
    value.map((descriptor) =>
      Object.freeze({
        id: descriptor.id,
        sourceModule: descriptor.sourceModule,
        sourceExport: descriptor.sourceExport,
      }),
    ),
  );
}
