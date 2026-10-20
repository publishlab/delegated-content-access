// @ts-check
//
// The HTTP half of server-side source provenance,
// docs/spec-proposal--html-content-map.md Section 8 items 1 and 2: fetch one locked
// delivery over an injected fetch, follow each redirect itself and admit every
// hop under the trusted source configuration. The policy decision per URL is
// `core-client/sourceProvenance.js` (`admitSourceUrl`, `admitRedirectTarget`),
// which also resolves a `Location` value; this module owns only the transport
// behavior around it: redirect statuses, the hop count, the final status and
// bounded body streaming. It uses no URL global, so it stays inside the extension
// adapter's lint scope.
//
// Every refusal is the map failure `source_refused`, except a body larger than
// the Section 5.4 document limit, which is `map_limit`.

import { dcaError } from "../../../core-shared/errors.js";
import {
  admitRedirectTarget,
  admitSourceUrl,
  sourceOrigin,
  sourceRefused,
} from "../core-client/sourceProvenance.js";

/** The redirect statuses a fetch with `redirect: "manual"` returns. */
const REDIRECTS = [301, 302, 303, 307, 308];

/**
 * The fetch the gateway injects: the Fetch standard's `fetch`, or anything that
 * answers the same status, headers and streaming body members.
 *
 * @typedef {(url: string, init: { method: 'GET', redirect: 'manual' }) => Promise<{
 *   status: number,
 *   headers: { get: (name: string) => string|null },
 *   body: { getReader: () => {
 *     read: () => Promise<{done: boolean, value?: Uint8Array}>,
 *     cancel: () => Promise<void>, releaseLock: () => void,
 *   } }|null,
 * }>} SourceFetch
 */

/**
 * Fetch one locked delivery under the source policy. Each redirect target is
 * admitted like the first URL; a redirect to another scheme or an unadmitted
 * URL, too many redirects, or a final status other than 200 is refused.
 *
 * @param {object} fetchRequest
 * @param {string} fetchRequest.url - as the caller named it
 * @param {readonly import('../core-client/sourceProvenance.js').PublisherSource[]} fetchRequest.sources
 * @param {SourceFetch} fetchRequest.fetch
 * @param {number} fetchRequest.maxRedirects
 * @param {number} fetchRequest.maxOctets - the document size limit (Section 5.4)
 * @returns {Promise<{ finalUrl: string, finalOrigin: string, bytes: Uint8Array }>}
 */
export async function fetchLockedDelivery({ url, sources, fetch, maxRedirects, maxOctets }) {
  if (
    !Number.isSafeInteger(maxOctets) ||
    maxOctets <= 0 ||
    !Number.isSafeInteger(maxRedirects) ||
    maxRedirects < 0
  ) {
    throw dcaError("bad_config", "source limits must be finite safe integers");
  }
  const first = admitSourceUrl(url, sources);
  if (first === null) throw sourceRefused("the source configuration does not admit this URL");
  let current = first;
  for (let redirects = 0; ; redirects += 1) {
    let response;
    try {
      response = await fetch(current, { method: "GET", redirect: "manual" });
    } catch {
      throw sourceRefused("the source did not answer");
    }
    if (response.status !== 200) await cancelUnreadBody(response.body);
    if (REDIRECTS.includes(response.status)) {
      if (redirects >= maxRedirects) throw sourceRefused("the source redirected too many times");
      const admitted = admitRedirectTarget(response.headers.get("location"), current, sources);
      if (admitted === null)
        throw sourceRefused("the source redirected to a URL the policy does not admit");
      current = admitted;
      continue;
    }
    if (response.status !== 200)
      throw sourceRefused(`the source answered status ${response.status}`);
    try {
      admitUtf8ContentType(response.headers.get("content-type"));
    } catch (cause) {
      await cancelUnreadBody(response.body);
      throw cause;
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      throw sourceRefused("the source must expose a streaming body");
    }
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        if (!(chunk.value instanceof Uint8Array))
          throw sourceRefused("the source stream did not supply bytes");
        if (chunk.value.byteLength > maxOctets - size) {
          throw dcaError("map_limit", `the locked document is larger than ${maxOctets} octets`);
        }
        size += chunk.value.byteLength;
        if (chunk.value.byteLength) chunks.push(chunk.value.slice());
      }
    } catch (cause) {
      try {
        await reader.cancel();
      } catch {
        /* Keep the original refusal. */
      }
      if (
        cause instanceof Error &&
        "code" in cause &&
        (cause.code === "map_limit" || cause.code === "source_refused")
      )
        throw cause;
      throw sourceRefused("the source body could not be read");
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { finalUrl: current, finalOrigin: sourceOrigin(current), bytes };
  }
}

/** Release a response that will not be consumed, including redirect bodies.
 * @param {Awaited<ReturnType<SourceFetch>>['body']} body
 * @returns {Promise<void>}
 */
async function cancelUnreadBody(body) {
  if (!body || typeof body.getReader !== "function") return;
  const reader = body.getReader();
  try {
    await reader.cancel();
  } catch {
    /* The status/redirect policy still decides the response. */
  } finally {
    reader.releaseLock();
  }
}

/** The server source contract accepts only UTF-8 or UTF8, case-insensitively.
 * @param {string} label @returns {void}
 */
export function admitUtf8Charset(label) {
  if (!["utf-8", "utf8"].includes(label.trim().toLowerCase())) {
    throw sourceRefused("the source declares an unsupported character encoding");
  }
}

/** The final response needs text/html with exactly one unambiguous UTF-8 charset.
 * Quoted parameter values may contain semicolons without declaring another
 * charset. Any malformed parameter or duplicate charset refuses the source.
 * @param {string|null} value @returns {void}
 */
export function admitUtf8ContentType(value) {
  if (typeof value !== "string") throw sourceRefused("the source has no Content-Type");
  const segments = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index++) {
    const char = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && char === "\\") {
      escaped = true;
      continue;
    }
    if (char === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && char === ";") {
      segments.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  if (quoted || escaped) throw sourceRefused("the source Content-Type has an unfinished quote");
  segments.push(value.slice(start).trim());
  if (segments.shift()?.toLowerCase() !== "text/html")
    throw sourceRefused("the source is not text/html");
  let charsetCount = 0;
  for (const segment of segments) {
    const match =
      /^([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([!#$%&'*+.^_`|~0-9A-Za-z-]+))$/.exec(
        segment,
      );
    if (!match) throw sourceRefused("the source Content-Type has a malformed parameter");
    if (match[1].toLowerCase() === "charset") {
      charsetCount++;
      admitUtf8Charset(match[2] === undefined ? match[3] : match[2].replace(/\\(.)/g, "$1"));
    }
  }
  if (charsetCount !== 1) throw sourceRefused("the source needs exactly one UTF-8 charset");
}
