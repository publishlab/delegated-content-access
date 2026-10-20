// The process boundary is deliberately small: one length-prefixed JSON value
// per frame on stdout, with diagnostics reserved for stderr.

import { isIdentifier, isSafeModulePath } from "./routing.mjs";

export const PROTOCOL_VERSION = 1;
export const DEFAULT_MAX_FRAME_BYTES = 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 5_000;

/** @param {object} value @param {string[]} keys */
function exactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

/** @param {unknown} value @param {number} [maximum] */
export function encodeFrame(value, maximum = DEFAULT_MAX_FRAME_BYTES) {
  const body = new TextEncoder().encode(JSON.stringify(value));
  if (body.byteLength > maximum) throw new RangeError(`bridge frame exceeds ${maximum} bytes`);
  const frame = new Uint8Array(4 + body.byteLength);
  new DataView(frame.buffer).setUint32(0, body.byteLength);
  frame.set(body, 4);
  return frame;
}

export class FrameDecoder {
  #pending = new Uint8Array();

  /** @param {Uint8Array} chunk @param {number} [maximum] */
  push(chunk, maximum = DEFAULT_MAX_FRAME_BYTES) {
    const joined = new Uint8Array(this.#pending.byteLength + chunk.byteLength);
    joined.set(this.#pending);
    joined.set(chunk, this.#pending.byteLength);
    const frames = [];
    let offset = 0;
    while (joined.byteLength - offset >= 4) {
      const size = new DataView(joined.buffer, joined.byteOffset + offset, 4).getUint32(0);
      if (size > maximum) throw new RangeError(`bridge frame exceeds ${maximum} bytes`);
      if (joined.byteLength - offset - 4 < size) break;
      const text = new TextDecoder().decode(joined.subarray(offset + 4, offset + 4 + size));
      try {
        frames.push(JSON.parse(text));
      } catch {
        throw new SyntaxError("bridge frame is not JSON");
      }
      offset += 4 + size;
    }
    this.#pending = joined.slice(offset);
    return frames;
  }

  finish() {
    if (this.#pending.byteLength !== 0) throw new SyntaxError("bridge stream ended mid-frame");
  }
}

/**
 * A call's `instances`: each entry marks one argument that stands for an
 * instance of a reference class, by the class's module and export. The
 * argument itself is the instance's data.
 *
 * @param {unknown} instances @param {unknown} input
 */
function isInstanceList(instances, input) {
  if (!Array.isArray(instances) || instances.length === 0 || !Array.isArray(input)) return false;
  const marked = new Set();
  return instances.every((entry) => {
    const valid =
      entry !== null &&
      typeof entry === "object" &&
      exactKeys(entry, ["argument", "sourceExport", "sourceModule"]) &&
      Number.isSafeInteger(entry.argument) &&
      entry.argument >= 0 &&
      entry.argument < input.length &&
      !marked.has(entry.argument) &&
      isSafeModulePath(entry.sourceModule) &&
      isIdentifier(entry.sourceExport);
    marked.add(entry?.argument);
    return valid;
  });
}

/**
 * A call's `receiver`: the handle of the object whose member the call runs,
 * in the exact handle layout.
 *
 * @param {unknown} receiver
 */
function isReceiver(receiver) {
  if (receiver === null || typeof receiver !== "object" || Array.isArray(receiver)) return false;
  const tag = /** @type {{ $type?: unknown, class?: unknown, handle?: unknown }} */ (receiver);
  const exact = exactKeys(tag, ["$type", "class", "handle"]);
  const named = typeof tag.class === "string" && tag.class.length > 0;
  const issued = typeof tag.handle === "string" && tag.handle.length > 0;
  return exact && tag.$type === "Handle" && named && issued;
}

/** @param {unknown} message */
export function assertRequest(message) {
  if (!message || typeof message !== "object") throw new TypeError("bridge request is an object");
  const request = /** @type {any} */ (message);
  if (request.version !== PROTOCOL_VERSION)
    throw new TypeError("unsupported bridge protocol version");
  if (typeof request.id !== "string" || request.id.length === 0)
    throw new TypeError("bridge request id is a non-empty string");
  if (
    request.type !== "describe" &&
    request.type !== "describeModule" &&
    request.type !== "call" &&
    request.type !== "dispose"
  )
    throw new TypeError("unknown bridge request type");
  if (request.type === "call") {
    if (Object.hasOwn(request, "target"))
      throw new TypeError("bridge call names its protocol in protocol, not target");
    if (request.protocol !== "dca-test-bridge/v1")
      throw new TypeError("bridge call protocol is dca-test-bridge/v1");
    if (typeof request.operation !== "string" || request.operation.length === 0)
      throw new TypeError("bridge call operation is a non-empty string");
    if (!Object.hasOwn(request, "input")) throw new TypeError("bridge call has encoded input");
    if (Object.hasOwn(request, "instances") && !isInstanceList(request.instances, request.input))
      throw new TypeError(
        "bridge call instances name distinct argument indexes, each with a class sourceModule and sourceExport",
      );
    if (Object.hasOwn(request, "receiver") && !isReceiver(request.receiver))
      throw new TypeError("bridge call receiver is one handle");
  }
  if (request.type === "describeModule") {
    if (typeof request.sourceModule !== "string" || request.sourceModule.length === 0)
      throw new TypeError("bridge module description has a source module");
  }
  return request;
}

/**
 * An observation's `declared` list: each entry names a position in the value,
 * as record member names and list indexes from the root, and the JS type the
 * test target itself gave the value there. `"all"` instead declares every
 * position.
 *
 * @param {unknown} declared
 */
function isDeclarationList(declared) {
  return (
    Array.isArray(declared) &&
    declared.every(
      (entry) =>
        entry !== null &&
        typeof entry === "object" &&
        exactKeys(entry, ["at", "type"]) &&
        ["record", "list", "Uint8Array"].includes(entry.type) &&
        Array.isArray(entry.at) &&
        entry.at.every(
          (/** @type {unknown} */ step) =>
            typeof step === "string" ||
            (typeof step === "number" && Number.isSafeInteger(step) && step >= 0),
        ),
    )
  );
}

/** @param {unknown} message @param {string | undefined} [expectedId] */
export function assertResponse(message, expectedId) {
  if (!message || typeof message !== "object") throw new TypeError("bridge response is an object");
  const response = /** @type {any} */ (message);
  if (response.version !== PROTOCOL_VERSION)
    throw new TypeError("unsupported bridge protocol version");
  if (typeof response.id !== "string" || response.id.length === 0)
    throw new TypeError("bridge response id is a non-empty string");
  if (expectedId !== undefined && response.id !== expectedId)
    throw new TypeError("bridge response id does not match its request");
  if (response.type !== "response") throw new TypeError("bridge response type is response");
  if (response.settled !== undefined && response.settled !== "promise")
    throw new TypeError('bridge response settled is "promise" when present');
  if (!response.result || typeof response.result !== "object")
    throw new TypeError("bridge response has a result");
  const result = response.result;
  if (
    result.kind === "observation" &&
    (exactKeys(result, ["kind", "value"]) ||
      (exactKeys(result, ["declared", "kind", "value"]) &&
        (result.declared === "all" || isDeclarationList(result.declared))))
  )
    return response;
  if (
    result.kind === "refusal" &&
    typeof result.code === "string" &&
    ((typeof result.message === "string" && exactKeys(result, ["code", "kind", "message"])) ||
      (typeof result.message === "string" &&
        typeof result.errorType === "string" &&
        result.errorType.length > 0 &&
        exactKeys(result, ["code", "errorType", "kind", "message"])) ||
      (result.message === undefined && exactKeys(result, ["code", "kind"])))
  ) {
    return response;
  }
  if (result.kind === "unsupported" && exactKeys(result, ["kind"])) return response;
  if (
    result.kind === "uncarried" &&
    typeof result.message === "string" &&
    exactKeys(result, ["kind", "message"])
  )
    return response;
  throw new TypeError("bridge response result is a known exact variant");
}
