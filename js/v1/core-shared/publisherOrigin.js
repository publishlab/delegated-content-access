// @ts-check

// Helpers for the publisher origin, a value outside the DCA document. In the
// browser profile, the publisher origin matches the page's exact URL origin and
// the request's HTTP Origin: scheme, host and port, with no path. The publisher
// carries it as delivery context, the issuer registers it beside a signing-key kid,
// and the client uses it to partition reusable period keys.

/**
 * Returns a canonical HTTP(S) origin, or null. The function requires the
 * canonical serialization so that publisher delivery, HTTP admission and cache
 * identity all use one spelling of the origin.
 *
 * @param {unknown} value
 * @returns {string|null}
 */
export function normalizePublisherOrigin(value) {
  if (typeof value !== "string" || value.length === 0 || value === "null") return null;

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.origin === "null" ||
    parsed.origin !== value
  ) {
    return null;
  }
  return parsed.origin;
}

/**
 * The hosts a development profile may deliver over http: `localhost`, any name
 * under it, and the loopback literal.
 *
 * @param {string} host - lowercase ASCII, as a canonical origin carries it
 * @returns {boolean}
 */
function loopbackHost(host) {
  return host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1";
}

/**
 * Returns the canonical origin a publisher may sign, or null. Production renders
 * use https. A caller turns on the development profile explicitly with
 * `developmentHttpOrigin`. The function then accepts http for a loopback host and
 * for nothing else, so a deployment that turned it on still cannot sign
 * `http://www.news-site.example`.
 *
 * The issuer reads the signed claim through the same call and its own copy of
 * the profile. A check that only compares the signed bytes with the observed
 * `Origin` header would pass an http delivery: a page served over http reports
 * the http origin, so the two values agree, but no production render uses http.
 *
 * A PHP counterpart, `Origin::canonical($value, $localhostHttp)`, uses the
 * same host set and the same opt-in.
 *
 * @param {unknown} value
 * @param {boolean} [developmentHttpOrigin] - the development profile
 * @returns {string|null}
 */
export function signableOrigin(value, developmentHttpOrigin = false) {
  const origin = normalizePublisherOrigin(value);
  if (origin === null || !origin.startsWith("http://")) return origin;

  return developmentHttpOrigin === true && loopbackHost(new URL(origin).hostname) ? origin : null;
}
