// @ts-check
// Publisher-to-issuer evidence only. Client-bound algorithms and general role
// duties do not establish either envelope construction (profiles Section 3.5).
export const ENVELOPE_ALGORITHMS = Object.freeze(["ecdh-p256", "rsa-oaep"]);
export const ENVELOPE_TAGS = Object.freeze(
  ENVELOPE_ALGORITHMS.flatMap((algorithm) =>
    ["publisher", "issuer"].map((role) => `envelope/${algorithm}/${role}`),
  ),
);

/**
 * Collect observations only from ordinary passing tests, never suites, skips
 * or TODOs. A tag describes focused evidence, not complete role conformance.
 * @param {import('./claim-index.js').ClaimTestEvent[]} events
 * @returns {string[]}
 */
export function observedEnvelopeTags(events) {
  const observed = new Set();
  const directive = (/** @type {unknown} */ value) => value === true || typeof value === "string";
  for (const event of events) {
    if (
      event.type !== "test:pass" ||
      event.data.details?.type !== "test" ||
      directive(event.data.skip) ||
      directive(event.data.todo)
    )
      continue;
    for (const tag of /** @type {string[]} */ (event.data.tags ?? []))
      if (ENVELOPE_TAGS.includes(tag)) observed.add(tag);
  }
  return [...observed].sort();
}

/**
 * Assess declared envelope support independently of the overall pilot verdict.
 * An RSA-only observation is useful narrower evidence, never baseline support.
 * Opaque-relay clients owe no publisher-to-issuer envelope observations.
 * @param {string[]} roles
 * @param {string[]} algorithms
 * @param {string[]} observed
 */
export function assessEnvelopeEvidence(roles, algorithms, observed) {
  const envelopeRoles = roles.filter((role) => ["publisher", "issuer"].includes(role));
  const declared = ENVELOPE_ALGORITHMS.filter((algorithm) => algorithms.includes(algorithm));
  const required = declared.flatMap((algorithm) =>
    envelopeRoles.map((role) => `envelope/${algorithm}/${role}`),
  );
  const passed = required.filter((tag) => observed.includes(tag));
  const missing = required.filter((tag) => !observed.includes(tag));
  const baselineSupport = envelopeRoles.length === 0 || declared.includes("ecdh-p256");
  return {
    scope: baselineSupport ? "baseline-envelope-support" : "narrower-envelope-behavior",
    declaredAlgorithms: declared,
    required,
    passed,
    missing,
    gaps: [
      ...(!baselineSupport
        ? [
            "RSA-only or absent envelope support is narrower than baseline; mandatory EC support is missing",
          ]
        : []),
      ...missing.map((tag) => `no passing envelope observation for ${tag}`),
    ],
  };
}
