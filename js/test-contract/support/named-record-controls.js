// @ts-check

// Harness-owned envelope candidates, independent of publisher/issuer source.
// Public fixture keys and fresh ephemeral pairs are used only in these tests.
const { subtle } = globalThis.crypto;

/**
 * Construct an ordinary 97-byte envelope under a literal, independently built
 * BIND. This is a semantic rival-preservation control, not a primitive vector.
 * @param {any} vector
 * @param {{contentName: string}|{accessGroup: string, period: string}} coordinate
 * @param {Uint8Array} key
 */
export async function namedRecordEnvelope(vector, coordinate, key) {
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  const recipient = await subtle.importKey(
    "jwk",
    vector.input.issuers[0].publicKeyJwk,
    algorithm,
    false,
    [],
  );
  const ephemeral = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey(algorithm, true, ["deriveBits"])
  );
  const shared = await subtle.deriveBits(
    { name: "ECDH", public: recipient },
    ephemeral.privateKey,
    256,
  );
  const aes = await subtle.importKey("raw", shared, "AES-GCM", false, ["encrypt"]);
  const payload = JSON.parse(
    Buffer.from(vector.expected.dcaData.resourceJWT.split(".")[1], "base64url").toString("utf8"),
  );
  const bind =
    "contentName" in coordinate
      ? `dca-bind-key-envelope|c|${payload.renderId}|${coordinate.contentName}`
      : `dca-bind-key-envelope|p|${payload.renderId}|${coordinate.accessGroup}|${coordinate.period}`;
  const encrypted = await subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(12), additionalData: new TextEncoder().encode(bind) },
    aes,
    key,
  );
  const point = await subtle.exportKey("raw", ephemeral.publicKey);
  return Buffer.concat([Buffer.from(point), Buffer.from(encrypted)]).toString("base64url");
}
