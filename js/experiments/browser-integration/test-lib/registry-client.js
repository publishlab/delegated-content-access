// @ts-check
// A checked client-side participant for the registry exchange proof. Discovery
// remains optional; this host helper validates its selected provider before use.

/**
 * @param {import("../implementation/registry.js").ClientRegistry} registry
 * @param {import("../implementation/registry.js").RegistryKey} key
 * @param {import("../implementation/content-handler.js").ConnectionSetup} setup
 * @returns {import("../implementation/content-handler.js").ContentConnection | null}
 */
export function connectSelected(registry, key, setup) {
  const provider = registry.lookup(key);
  if (provider === null) return null; // Pending is host policy, never another key.
  if (!("connect" in provider) || typeof provider.connect !== "function") {
    throw new Error("selected provider is not a content handler");
  }
  const handler = /** @type {import("../implementation/content-handler.js").ContentHandler} */ (
    provider
  );
  return handler.connect(setup);
}
