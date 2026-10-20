// @ts-check
//
// Web Streams compresses publisher input. The client default uses the strict
// inflater, which checks one complete gzip member. The native decompressor is
// available separately for callers that do not claim the DCA gzip profile.
//
// This extension is gzip and nothing else. `gzip` is one layer in the base
// representation list; another compression supplies another registry entry.
//
// A composition injects the gzip implementation, not the encoding: a runtime
// without Web Streams, a V8 embedding bridging PHP's `gzencode`, hands
// `CompressingSealer` and `openEncodedContent` its own `{ encode, decode }`.
//
// The bytes handed in are copied before they enter a stream, so a caller that
// reuses its buffer cannot change what was already encoded, and a caller that
// hands over a view it still reads gets it back untouched.

import { dcaError } from "../../../core-shared/errors.js";
import { decode as strictDecode } from "./inflate/inflate.js";

/** The one content-encoding layer this extension writes. */
export const ENCODING = "gzip";

/**
 * The extension API value that leaves a representation unchanged. It is never
 * emitted as a layer; an unchanged representation has no added gzip entry.
 */
export const IDENTITY = "identity";

/**
 * Everything a transform stream produced, in one buffer.
 *
 * @param {ReadableStream<Uint8Array>} readable
 * @returns {Promise<Uint8Array>}
 */
async function collect(readable) {
  const reader = readable.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  let length = 0;

  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    length += value.length;
  }

  const out = new Uint8Array(length);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/**
 * One buffer through one transform stream. Reading starts before the write, so
 * a body larger than the stream's internal queue does not deadlock on its own
 * backpressure, and both halves are settled before anything is thrown: a
 * rejected half nobody awaited would surface later as an unhandled rejection.
 *
 * @param {Uint8Array} bytes
 * @param {{ readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array> }} transform
 * @param {string} what - for the message
 * @returns {Promise<Uint8Array>}
 */
async function through(bytes, transform, what) {
  const collected = collect(transform.readable);
  const writer = transform.writable.getWriter();
  const written = (async () => {
    await writer.write(Uint8Array.from(bytes));
    await writer.close();
  })();

  const [write, read] = await Promise.allSettled([written, collected]);
  const subject = what === "decode" ? "a gzip stream" : "a buffer this stream accepts";
  if (write.status === "rejected") {
    throw dcaError("bad_encoding", `gzip ${what} failed: the bytes are not ${subject}`);
  }
  if (read.status === "rejected") {
    throw dcaError("bad_encoding", `gzip ${what} failed: the bytes are not ${subject}`);
  }
  return read.value;
}

/**
 * @param {Uint8Array} bytes - copied before use
 * @returns {Promise<Uint8Array>} the gzip stream over those bytes
 */
export function encode(bytes) {
  return through(bytes, new CompressionStream(ENCODING), "encode");
}

/**
 * @param {Uint8Array} bytes - copied before use
 * @returns {Promise<Uint8Array>} the bytes that stream carries
 */
export function decodeWebStreams(bytes) {
  return through(bytes, new DecompressionStream(ENCODING), "decode");
}

/** Strict single-member decoder used by normal client composition. */
export const decode = strictDecode;

/**
 * One gzip implementation, as both roles take it.
 *
 * @typedef {object} Gzip
 * @property {(bytes: Uint8Array) => Promise<Uint8Array>|Uint8Array} encode
 * @property {(bytes: Uint8Array, budget?: { maxOutputBytes: number }) => Promise<Uint8Array>|Uint8Array} decode
 */

/**
 * Native Web Streams pair for explicit opt-in. Its decoder does not establish
 * the strict single-member contract; normal client composition uses `decoders`.
 *
 * @type {Gzip}
 */
export const webStreamsGzip = { encode, decode: decodeWebStreams };

/** The decoder registry entry a client composition injects into base. */
export const decoders = Object.freeze({ [ENCODING]: decode });
