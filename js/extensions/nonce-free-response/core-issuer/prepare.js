// @ts-check
// Provisional controlled traversal: no stock resolver or KeyDelivery integration.
import { base64urlEncode } from "../../../core-shared/codec.js";
import { binaryStringBytes } from "../../../core-shared/binaryStrings.js";
import { encrypt } from "../../../core-shared/aead.js";
import { own, setOwn } from "../../../core-shared/wire.js";
import {
  recordPath,
  settleComposedSections,
} from "../../../core-shared--client-issuer/responseKeys.js";
import {
  NO_COMPOSED_KINDS,
  kindDescriptor,
  keyKindContext,
} from "../../client-bound-transport/core-shared--client-issuer/keyKind.js";
import { agreement, deriveEntryKey, entryInfo } from "../core-shared--client-issuer/entry.js";

const { subtle } = globalThis.crypto;
/** @param {any} body @param {readonly string[]} path */
const read = (body, path) => path.reduce((node, member) => own(node, member), body);
/** @param {any} body @param {string[]} path @param {any} value */
function write(body, path, value) {
  let parent = body;
  // structuredClone owns the graph but preserves aliases. Copy each ancestor
  // before replacing an entry so another response path keeps its ciphertext.
  for (const name of path.slice(0, -1)) {
    const source = own(parent, name);
    const child = Array.isArray(source) ? [...source] : { ...source };
    setOwn(parent, name, child);
    parent = child;
  }
  setOwn(parent, path.at(-1) ?? "", value);
}

/** @param {any} body @param {readonly Readonly<import("../../../core-shared--client-issuer/responseKeys.js").ComposedSection>[]} sections */
function* positions(body, sections) {
  const base = [
    { path: ["keys", "contentKeys"], fields: ["contentName"], keyKind: "contentKey" },
    { path: ["keys", "periodKeys"], fields: ["accessGroup", "period"], keyKind: "periodKey" },
    { path: ["keys", "chainKeys"], fields: ["accessGroup", "cutoff"], keyKind: "chainKey" },
  ];
  for (const section of [...base, ...sections]) {
    const parent = read(body, section.path.slice(0, -1));
    const member = section.path.at(-1) ?? "";
    if (parent === null || typeof parent !== "object" || !Object.hasOwn(parent, member)) continue;
    const records = own(parent, member);
    // Consumer traversal may ignore unusable candidates. A producer must not
    // return any selected plaintext key merely because its record is malformed.
    if (!Array.isArray(records)) throw new Error("delivered key collection must be an array");
    for (const [index, record] of records.entries()) {
      const coordinate = recordPath(record, section.fields);
      if (coordinate === null) throw new Error("invalid delivered key record");
      yield {
        // Array position locates output only; the construction binds the
        // original semantic coordinate, unchanged by record permutation.
        path: [...section.path, ...coordinate],
        location: [...section.path, String(index), "key"],
        kind: section.keyKind,
        value: own(record, "key"),
      };
    }
  }
}

/**
 * @param {JsonWebKey} clientPublicKey
 * @param {{composedSections?: import("../../../core-shared--client-issuer/responseKeys.js").ComposedSection[], composedKinds?: Readonly<Record<string, Readonly<import("../../client-bound-transport/core-shared--client-issuer/keyKind.js").KindDescriptor>>>, ephemeralKeyPair?: CryptoKeyPair}} [options]
 */
export async function preflight(
  clientPublicKey,
  { composedSections = [], composedKinds = NO_COMPOSED_KINDS, ephemeralKeyPair } = {},
) {
  kindDescriptor("contentKey", composedKinds);
  const sections = settleComposedSections(composedSections);
  const recipient = structuredClone(clientPublicKey);
  // Normal callers always generate a fresh pair. Injection is for deterministic
  // tests only: a pair must never be reused for another preflight.
  const pair =
    ephemeralKeyPair ??
    (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]));
  /** @type {CryptoKey|null} */
  let material = await agreement(recipient, pair.privateKey);
  const exported = await subtle.exportKey("jwk", pair.publicKey);
  const transport = {
    publicKey: { kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y },
  };
  return {
    /** @param {any} body */
    prepare(body) {
      // Claim before any await, including failed/empty preparation.
      if (material === null)
        return Promise.reject(new Error("response preparation already consumed"));
      const ownedMaterial = material;
      material = null;
      return (async () => {
        // Capture selected coordinates, bytes and AAD before crypto yields.
        // A plain clone gives this prototype an output it owns, not a batch API.
        const result = structuredClone(body);
        const seen = new Set();
        const entries = [...positions(result, sections)].map(({ path, location, kind, value }) => {
          const { width } = kindDescriptor(kind, composedKinds);
          const bytes = value instanceof Uint8Array ? value.slice() : binaryStringBytes(value);
          if (bytes === null || bytes.length !== width)
            throw new Error("wrong delivered key width");
          const info = entryInfo(kind, path);
          // A repeated kind/path would reuse the same entry key and zero IV.
          // Admit the complete batch before deriving or encrypting any entry.
          const identity = base64urlEncode(info);
          if (seen.has(identity)) throw new Error("duplicate response entry coordinate");
          seen.add(identity);
          return {
            location,
            bytes,
            info,
            aad: keyKindContext(kind, composedKinds),
          };
        });
        for (const { location, bytes, info, aad } of entries) {
          const key = await deriveEntryKey(ownedMaterial, info, ["encrypt"]);
          write(result, location, {
            key: base64urlEncode(await encrypt(key, new Uint8Array(12), bytes, aad, 32)),
          });
        }
        setOwn(result, "transport", structuredClone(transport));
        return result;
      })();
    },
  };
}
