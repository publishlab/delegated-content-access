#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { resolve, relative } from "node:path";

import {
  FrameDecoder,
  PROTOCOL_VERSION,
  assertRequest,
  encodeFrame,
} from "../_shared/protocol.mjs";
import {
  decodeValueAsync,
  encodeValue,
  encodeValueAsync,
  runtimeValueTypes,
} from "../_shared/serializer.mjs";

const configuredRoot = process.env.DCA_TARGET_ROOT;
if (configuredRoot === undefined || configuredRoot === "")
  throw new TypeError("DCA_TARGET_ROOT names the test-target root; this adapter has no default");
const targetRoot = resolve(configuredRoot);
const bindings = new Map();
const modules = new Map();
/** @type {Array<{ constructor: Function, id: string }>} */
const errorTypes = [];
/**
 * Each exported class a module description declared, by its prototype. Its
 * instances cross as handles; an instance of any other class does not.
 *
 * @type {Map<object, { id: string, prototype: object }>}
 */
const classes = new Map();
/**
 * Each instance member a class description declared, by its operation ID.
 *
 * @type {Map<string, { classId: string, prototype: object, method: Function, callShape: "sync" | "async" }>}
 */
const classMembers = new Map();
/**
 * Each declared class's constructor, by its operation ID.
 *
 * @type {Map<string, Function>}
 */
const constructorCalls = new Map();

/**
 * This adapter process's session. A handle names an object only here: the
 * random part keeps another process's handle from naming one of these.
 */
const session = randomBytes(8).toString("base64url");
let issuedHandles = 0;
/** @type {Map<string, object>} */
const liveObjects = new Map();
/** @type {WeakMap<object, string>} */
const handleIds = new WeakMap();

/**
 * A refusal of the bridge itself: a handle this session did not issue, or a
 * receiver that does not fit the member. It answers as an adapter refusal,
 * never as a target error.
 */
class HandleRefusal extends Error {}

/** @type {import("../_shared/serializer.mjs").HandleCodec} */
const handles = {
  encode(value) {
    const described = classes.get(/** @type {object} */ (Object.getPrototypeOf(value)));
    if (described === undefined) return undefined;
    let handle = handleIds.get(value);
    if (handle === undefined) {
      issuedHandles += 1;
      handle = `h-${session}-${issuedHandles}`;
      handleIds.set(value, handle);
      liveObjects.set(handle, value);
    }
    return { $type: "Handle", class: described.id, handle };
  },
  decode(tag) {
    const object = liveObjects.get(tag.handle);
    if (object === undefined) throw new HandleRefusal("bridge handle is not live in this session");
    const described = classes.get(/** @type {object} */ (Object.getPrototypeOf(object)));
    if (described?.id !== tag.class)
      throw new HandleRefusal("bridge handle names another class than its object has");
    return object;
  },
};

/** @param {string} sourceModule */
function modulePath(sourceModule) {
  if (!/^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.m?js$/.test(sourceModule))
    throw new TypeError("bridge source module is a safe relative JavaScript path");
  const path = resolve(targetRoot, sourceModule);
  if (relative(targetRoot, path).startsWith(".."))
    throw new TypeError("bridge source module stays below the test-target root");
  return path;
}

/**
 * A generator returns an iterator, which is no bridge value, so generator
 * functions stay reference-owned.
 */
const NOT_DIRECT = ["AsyncFunction", "GeneratorFunction", "AsyncGeneratorFunction"];

/** @param {unknown} value */
function directFunction(value) {
  return (
    typeof value === "function" &&
    !Function.prototype.toString.call(value).startsWith("class") &&
    !NOT_DIRECT.includes(value.constructor?.name)
  );
}

/** @param {unknown} value */
function asyncFunction(value) {
  return typeof value === "function" && value.constructor?.name === "AsyncFunction";
}

/** @param {unknown} value */
function bridgeValue(value) {
  try {
    encodeValue(value);
    return true;
  } catch {
    return false;
  }
}

/** @param {unknown} value @returns {value is Function} */
function classConstructor(value) {
  return typeof value === "function" && Function.prototype.toString.call(value).startsWith("class");
}

/**
 * The methods an instance of `constructor` has, own or inherited, below
 * `Object.prototype`: every data member whose value is a plain or async
 * function. Getters, setters, generators and private members are left out.
 *
 * @param {Function} constructor
 * @returns {[string, Function][]}
 */
function instanceMethods(constructor) {
  /** @type {Map<string, Function>} */
  const found = new Map();
  /** @type {Set<string>} */
  const seen = new Set();
  let prototype = constructor.prototype;
  while (prototype !== null && prototype !== Object.prototype) {
    for (const name of Object.getOwnPropertyNames(prototype)) {
      if (seen.has(name)) continue;
      seen.add(name);
      const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
      const value = descriptor?.value;
      const callable = directFunction(value) || asyncFunction(value);
      // A getter or other non-method also shadows an inherited method.
      const member = callable && name !== "constructor";
      if (member) found.set(name, /** @type {Function} */ (value));
    }
    prototype = Object.getPrototypeOf(prototype);
  }
  return [...found].sort(([left], [right]) => left.localeCompare(right));
}

/**
 * Declares an exported class: its instances cross as handles, each method
 * becomes a member operation, and its constructor an operation that answers
 * a new instance. A class exported twice is declared once.
 *
 * @param {string} sourceModule @param {string} sourceExport @param {Function} constructor
 */
function describeClass(sourceModule, sourceExport, constructor) {
  const prototype = constructor.prototype;
  if (classes.has(prototype)) return undefined;
  const id = `class-${Buffer.from(`${sourceModule}\0${sourceExport}`).toString("base64url")}`;
  classes.set(prototype, { id, prototype });
  const members = instanceMethods(constructor).map(([sourceMember, method]) => {
    const operation = `op-${Buffer.from(`${sourceModule}\0${sourceExport}\0${sourceMember}`).toString("base64url")}`;
    const callShape = asyncFunction(method) ? "async" : "sync";
    classMembers.set(operation, { classId: id, prototype, method, callShape });
    return { id: operation, sourceMember, callShape };
  });
  const construct = `new-${Buffer.from(`${sourceModule}\0${sourceExport}`).toString("base64url")}`;
  constructorCalls.set(construct, constructor);
  return { id, sourceExport, construct: { id: construct }, members };
}

/** @param {unknown} value */
function errorConstructor(value) {
  return (
    typeof value === "function" &&
    value.prototype &&
    Object.prototype.isPrototypeOf.call(Error.prototype, value.prototype)
  );
}

/** @param {string} sourceModule @param {string} sourceExport */
function errorId(sourceModule, sourceExport) {
  return `error-${Buffer.from(`${sourceModule}\0${sourceExport}`).toString("base64url")}`;
}

/** @param {string} sourceModule */
async function describeModule(sourceModule) {
  const cached = modules.get(sourceModule);
  if (cached) return cached;
  const namespace = await import(new URL(`file://${modulePath(sourceModule)}`).href);
  const errors = Object.entries(namespace)
    .filter(([, value]) => errorConstructor(value))
    .map(([sourceExport]) => ({
      id: errorId(sourceModule, sourceExport),
      sourceModule,
      sourceExport,
    }));
  for (const descriptor of errors)
    errorTypes.push({ constructor: namespace[descriptor.sourceExport], id: descriptor.id });
  const members = Object.entries(namespace)
    // Discovery must not make an otherwise usable module fail merely because
    // it exports a runtime object (for example a RegExp) that the bridge value
    // contract deliberately excludes. Such exports remain reference-owned;
    // callable functions and serializable values are the portable surface.
    .filter(
      ([, value]) =>
        directFunction(value) ||
        asyncFunction(value) ||
        (typeof value !== "function" && bridgeValue(value)),
    )
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([sourceExport, value]) => ({
      id: `op-${Buffer.from(`${sourceModule}\0${sourceExport}`).toString("base64url")}`,
      sourceExport,
      callShape: directFunction(value) ? "sync" : asyncFunction(value) ? "async" : "value",
    }));
  const declared = Object.entries(namespace)
    .filter(([, value]) => classConstructor(value) && !errorConstructor(value))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([sourceExport, value]) => describeClass(sourceModule, sourceExport, value))
    .filter((entry) => entry !== undefined);
  const entry = { members, classes: declared, namespace };
  modules.set(sourceModule, entry);
  for (const member of members)
    if (member.callShape === "sync" || member.callShape === "async")
      bindings.set(member.id, namespace[member.sourceExport]);
  return entry;
}

/**
 * The call's arguments with each one the frame marks in `instances` rebuilt
 * as `new Class(data)`, the class imported from the test target's own module.
 * Unmarked arguments stay the decoded values.
 *
 * @param {unknown[]} input
 * @param {{ argument: number, sourceModule: string, sourceExport: string }[] | undefined} instances
 */
async function rebuildInstances(input, instances) {
  if (instances === undefined) return input;
  const rebuilt = [...input];
  for (const { argument, sourceModule, sourceExport } of instances) {
    const namespace = await import(new URL(`file://${modulePath(sourceModule)}`).href);
    const type = namespace[sourceExport];
    if (typeof type !== "function" || !type.prototype)
      throw new TypeError(`${sourceModule} exports no class ${sourceExport}`);
    rebuilt[argument] = new type(input[argument]);
  }
  return rebuilt;
}

/**
 * @param {string} id @param {unknown} result
 * @param {boolean} [promised] the target entry returned a promise to a sync call
 */
function response(id, result, promised = false) {
  process.stdout.write(
    encodeFrame({
      version: PROTOCOL_VERSION,
      type: "response",
      id,
      result,
      ...(promised ? { settled: "promise" } : {}),
    }),
  );
}

/** @param {unknown} error */
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/** @param {unknown} error */
function errorCode(error) {
  return error && typeof error === "object" && "code" in error && typeof error.code === "string"
    ? error.code
    : "adapter_refusal";
}

/**
 * The object a member call runs on. A member needs the handle of an object of
 * its own class; an export takes no receiver.
 *
 * @param {{ receiver?: import("../_shared/serializer.mjs").HandleTag }} request
 * @param {{ prototype: object } | undefined} member
 * @returns {object | undefined}
 */
function receiverFor(request, member) {
  const tag = request.receiver;
  if (member === undefined && tag !== undefined)
    throw new HandleRefusal("an export call takes no receiver");
  if (member === undefined) return undefined;
  if (tag === undefined) throw new HandleRefusal("a member call needs a receiver handle");
  const object = /** @type {object} */ (handles.decode(tag));
  if (Object.getPrototypeOf(object) !== member.prototype)
    throw new HandleRefusal("the receiver is no object of the member's class");
  return object;
}

/**
 * The observation of a call that returned. The test target answered, so a
 * result that is no bridge value, or arguments the call changed, are limits
 * of the bridge: the answer is `uncarried`, never a target refusal.
 *
 * @param {unknown[]} input @param {string} before @param {unknown} produced
 */
async function observation(input, before, produced) {
  try {
    if (JSON.stringify(await encodeValueAsync(input, handles)) !== before)
      return { kind: "uncarried", message: "the call changed its arguments" };
    // Every value here is a JS value with one reading, so the driver reads
    // none of it by the reference type. An object of a declared class goes
    // out as its handle.
    const value = await encodeValueAsync(produced, handles);
    return { kind: "observation", value, declared: "all" };
  } catch (error) {
    return { kind: "uncarried", message: errorMessage(error) };
  }
}

/** @param {unknown} raw */
async function handle(raw) {
  let request;
  try {
    request = assertRequest(raw);
  } catch (error) {
    process.stderr.write(`bridge request refused: ${errorMessage(error)}\n`);
    return;
  }
  if (request.type === "describe") {
    response(request.id, {
      kind: "observation",
      value: encodeValue({
        identity: {
          bridge: "js",
          adapterVersion: "1",
          targetVersion: "reference",
        },
        capabilities: {
          valueTypes: runtimeValueTypes,
          moduleDiscovery: true,
        },
        errorTypes: [],
      }),
    });
    return;
  }
  if (request.type === "dispose") {
    // The session ends: no handle names an object any more.
    liveObjects.clear();
    response(request.id, { kind: "observation", value: null });
    process.nextTick(() => process.exit(0));
    return;
  }
  if (request.type === "describeModule") {
    try {
      const described = await describeModule(request.sourceModule);
      const classesPart = described.classes.length === 0 ? {} : { classes: described.classes };
      response(request.id, {
        kind: "observation",
        value: encodeValue({ members: described.members, ...classesPart }),
      });
    } catch (error) {
      response(request.id, {
        kind: "refusal",
        code: errorCode(error),
        message: errorMessage(error),
      });
    }
    return;
  }
  const operation = bindings.get(request.operation);
  const member = classMembers.get(request.operation);
  const constructor = constructorCalls.get(request.operation);
  const known =
    typeof operation === "function" || member !== undefined || constructor !== undefined;
  if (!known) return response(request.id, { kind: "unsupported" });
  let input;
  let before;
  let produced;
  // A sync entry that returns a promise settles here; the response says so,
  // and the driver hands the test a promise with the same outcome.
  let promised = false;
  try {
    input = await decodeValueAsync(request.input, handles);
    if (!Array.isArray(input)) throw new TypeError("operation input is an argument list");
    const receiver = receiverFor(request, member);
    // The arguments check reads the decoded data, which a rebuilt instance
    // wraps, so a call that changes an instance's data changed its arguments.
    // A handle argument reads as its handle: the object behind it may change.
    before = JSON.stringify(await encodeValueAsync(input, handles));
    const values = await rebuildInstances(input, request.instances);
    let returned;
    if (constructor !== undefined) returned = Reflect.construct(constructor, values);
    else if (member !== undefined) returned = member.method.apply(receiver, values);
    else returned = operation.apply(receiver, values);
    const declaredAsync =
      member === undefined ? asyncFunction(operation) : member.callShape === "async";
    promised = !declaredAsync && returned instanceof Promise;
    produced = await returned;
  } catch (error) {
    const mapped =
      error && typeof error === "object"
        ? (errorTypes.find(({ constructor }) => error.constructor === constructor)?.id ??
          errorTypes.find(({ constructor }) => error instanceof constructor)?.id)
        : undefined;
    const native =
      error instanceof DOMException
        ? `native-dom:${error.name}`
        : error instanceof Error &&
            [
              "Error",
              "TypeError",
              "RangeError",
              "ReferenceError",
              "SyntaxError",
              "EvalError",
              "URIError",
              "AggregateError",
            ].includes(error.constructor?.name)
          ? `native:${error.constructor.name}`
          : undefined;
    response(
      request.id,
      {
        kind: "refusal",
        code: errorCode(error),
        message: errorMessage(error),
        ...(mapped ? { errorType: mapped } : native ? { errorType: native } : {}),
      },
      promised,
    );
    return;
  }
  response(request.id, await observation(input, before, produced), promised);
}

const decoder = new FrameDecoder();
let requestQueue = Promise.resolve();
/** @param {unknown} error */
function protocolFailure(error) {
  process.stderr.write(`bridge protocol failure: ${errorMessage(error)}\n`);
  process.exitCode = 2;
}
process.stdin.on("data", (chunk) => {
  let frames;
  try {
    frames = decoder.push(chunk);
  } catch (error) {
    protocolFailure(error);
    return;
  }
  for (const frame of frames) {
    requestQueue = requestQueue.then(() => handle(frame)).catch(protocolFailure);
  }
});
process.stdin.on("end", () => {
  requestQueue = requestQueue
    .then(() => decoder.finish())
    .catch((error) => {
      process.stderr.write(`bridge protocol failure: ${errorMessage(error)}\n`);
      process.exitCode = 2;
    });
});
