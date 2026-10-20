// @ts-check

// Harness-owned inputs, signed independently of the implementation under test.
// These are semantic admission controls, not new primitive corpus vectors.

const { subtle } = globalThis.crypto;
const algorithm = { name: "ECDSA", namedCurve: "P-256" };

/** @param {any} vector @returns {Promise<{ registered: string, attacker: string }>} */
export async function registeredJwsControls(vector) {
  const fixture = vector.input.signingKeys[0];
  const trusted = await subtle.importKey("jwk", fixture.privateKeyJwk, algorithm, false, ["sign"]);
  const attacker = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey(algorithm, true, ["sign", "verify"])
  );
  const jwk = await subtle.exportKey("jwk", attacker.publicKey);
  const header = {
    alg: "ES256",
    typ: "JWT",
    kid: fixture.kid,
    jwk,
    jku: "https://untrusted.invalid/keys.json",
    x5u: "https://untrusted.invalid/certificate.pem",
  };
  const encode = (/** @type {unknown} */ value) =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const original = vector.expected.dcaData.resourceJWT.split(".");
  const input = `${encode(header)}.${original[1]}`;
  const sign = async (/** @type {CryptoKey} */ key) =>
    `${input}.${Buffer.from(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(input))).toString("base64url")}`;
  return { registered: await sign(trusted), attacker: await sign(attacker.privateKey) };
}
