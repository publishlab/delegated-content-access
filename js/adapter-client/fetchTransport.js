// @ts-check
// Browser Fetch port for the delivery client's transport.post contract.
// An unseen HTTP outcome is indeterminate; only an observed status is an
// answer. Hosts choose credentials and any whole-acquisition cancellation.

import { dcaError } from "../core-shared/errors.js";

const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

/** @param {unknown} cause */
function isFetchFailure(cause) {
  return (
    cause instanceof TypeError || (cause instanceof DOMException && cause.name === "AbortError")
  );
}

/** @param {unknown} cause */
function indeterminate(cause) {
  const error = dcaError("indeterminate_transport", "Fetch did not expose an issuer response");
  error.cause = cause;
  return error;
}

/** @param {unknown} cause @param {AbortSignal|undefined} signal @returns {never} */
function rethrowFetchFailure(cause, signal) {
  if (signal?.aborted) throw cause;
  if (isFetchFailure(cause)) throw indeterminate(cause);
  throw cause;
}

/** @param {Response} response */
function discardBody(response) {
  try {
    void response.body?.cancel().catch(() => {});
  } catch {
    // Diagnostic-body cleanup cannot erase a known HTTP status.
  }
}

/** @param {unknown} cause @param {AbortSignal|undefined} signal @returns {null} */
function unusableBodyOrAbort(cause, signal) {
  if (signal?.aborted) throw cause;
  if (isFetchFailure(cause)) return null;
  throw cause;
}

/**
 * Read at most maxBytes of one body. A body whose limit is exceeded yields no
 * DCA result; each chunk is checked before being copied or accumulated.
 * @param {Response} response
 * @param {number} maxBytes
 * @param {AbortSignal|undefined} signal
 * @returns {Promise<Uint8Array|null>}
 */
async function boundedBody(response, maxBytes, signal) {
  if (!response.body) return null;
  let reader;
  try {
    reader = response.body.getReader();
  } catch (cause) {
    return unusableBodyOrAbort(cause, signal);
  }
  /** @type {Uint8Array[]} */
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      let step;
      try {
        step = await reader.read();
      } catch (cause) {
        return unusableBodyOrAbort(cause, signal);
      }
      if (step.done) break;
      if (!(step.value instanceof Uint8Array)) return null;
      if (step.value.length > maxBytes - length) {
        try {
          void reader.cancel().catch(() => {});
        } catch {
          // A rejected cancellation does not turn an oversized body into data.
        }
        return null;
      }
      length += step.value.length;
      chunks.push(Uint8Array.from(step.value));
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

/** @param {Uint8Array|null} bytes */
function jsonBody(bytes) {
  if (bytes === null) return undefined;
  let text;
  try {
    // Preserve a BOM so this one step, and only this step, removes it.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.startsWith("\uFEFF")) text = text.slice(1);
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * @param {{
 *   fetch?: typeof globalThis.fetch,
 *   credentials?: RequestCredentials,
 *   maxResponseBytes?: number,
 *   signal?: AbortSignal
 * }} [options]
 */
export function createFetchTransport({
  fetch: fetchRequest = globalThis.fetch,
  credentials = "omit",
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  signal,
} = {}) {
  if (
    typeof fetchRequest !== "function" ||
    !["omit", "same-origin", "include"].includes(credentials) ||
    !Number.isSafeInteger(maxResponseBytes) ||
    maxResponseBytes < 1 ||
    (signal !== undefined &&
      (typeof signal?.aborted !== "boolean" || typeof signal.addEventListener !== "function"))
  ) {
    throw dcaError(
      "bad_config",
      "Fetch transport needs Fetch, credentials, a positive response cap and optional AbortSignal",
    );
  }

  return Object.freeze({
    /** @param {string} url @param {object} request @param {{ origin: string }} _context */
    async post(url, request, _context) {
      void _context;
      // A circular or otherwise unserializable caller value is a programming
      // error, outside the Fetch boundary.
      const body = JSON.stringify(request);
      if (typeof body !== "string") throw dcaError("bad_config", "a Fetch request is JSON data");
      if (signal?.aborted) throw signal.reason ?? new DOMException("cancelled", "AbortError");

      /** @type {Response} */
      let response;
      try {
        response = await fetchRequest(url, {
          method: "POST",
          headers: { Accept: "application/json", "Content-Type": "application/json" },
          credentials,
          redirect: "manual",
          cache: "no-store",
          body,
          ...(signal ? { signal } : {}),
        });
      } catch (cause) {
        rethrowFetchFailure(cause, signal);
      }
      if (response.type === "opaque" || response.type === "opaqueredirect" || response.status === 0)
        throw indeterminate(new TypeError("Fetch response is opaque"));
      const contentType = response.headers.get("content-type");
      if (response.status !== 200) {
        discardBody(response);
        return { status: response.status, contentType, body: undefined };
      }
      const bytes = await boundedBody(response, maxResponseBytes, signal);
      return { status: response.status, contentType, body: jsonBody(bytes) };
    },
  });
}
