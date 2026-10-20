import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * What a JVM observes when it is asked to perform one of seven library calls,
 * and nothing about whether that observation is right.
 *
 * The bridge reads a single
 * `dca-operation-bridge-v1` JSON document from stdin, computes one observation
 * per request, writes a single JSON document to stdout and exits 0. Human
 * diagnostics go to stderr; nothing reads a result out of stderr, so a bridge
 * may say whatever it likes there. This file was written against
 * `../../../_shared/contract/v1/bridge.md` and nothing else.
 *
 * Each operation runs one stock JDK call over octets the request carries:
 * decode a strict base64url field, derive octets with HKDF-SHA-256, open and
 * seal an AES-GCM carrier, agree a P-256 ECDH secret, encode a P-256 public
 * point, and open an RSA-OAEP ciphertext. The bridge joins nothing, slices
 * nothing and derives nothing on any specification's behalf.
 *
 * This file holds no expected value, no comparison, no `held`, `disagreed` or
 * `incomplete` word, no pass count and no total. It never opens the case
 * corpus. The request it is handed carries no `expected` and no `class`. It
 * copies the identifier back into the result and reads it for nothing else.
 *
 * The bridge answers a defined refusal inside an exit-0 result.
 * `invalid_base64url`, `authentication_failed` and `unseal_failed` are
 * observations, and refusing correctly is one of the behaviours under test. The
 * bridge exits nonzero with a stderr line and writes no partial results for a
 * request it cannot serve at all: an unparseable batch, an unknown operation, a
 * key of some width other than 16 or 32 bytes, a nonce of some width other than
 * 12 bytes, a key this JDK cannot import, or an input shape outside the
 * contract. The runner reads that as a run that could not be completed.
 * `seal-aes-gcm`, `hkdf-sha256`, `ecdh-p256` and `p256-point` define no
 * refusal: a correct implementation answers every input they accept, so a
 * failure there leaves the bridge unable to serve the request.
 *
 * The bridge checks every shape it reads and reads each one as closed. The
 * envelope carries `protocol` and `requests`, a request row carries `id`, `op`
 * and `input`, and an input carries exactly the members its operation names. When
 * a member nobody named arrives, the harness is speaking a protocol this bridge has not
 * agreed to, and the bridge refuses the batch.
 *
 * One reader reads the batch. The JDK ships no JSON parser, so the lane pins
 * Jackson, and {@link Json} beside this file is the object model over it that
 * reads stdin. Every operation below sees String, Boolean, Long, Double, List
 * and {@link Json.OMap}, and no Jackson type.
 *
 * Requires a JDK. Verified on Temurin 21.0.12.1.
 *
 * Run (`../bridge` does this; by hand it is the same):
 *   printf '%s\n' '&lt;batch json&gt;' | java -cp &lt;build-dir&gt; Bridge
 */
public final class Bridge {

    private static final String BATCH_PROTOCOL = "dca-operation-bridge-v1";

    /** RFC 4648 section 5's alphabet and nothing else, so `+`, `/`, `=` and whitespace all fail here. */
    private static final Pattern BASE64URL_ALPHABET = Pattern.compile("[A-Za-z0-9_-]+");

    private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /** The two AES key widths the contract carries: 16 bytes picks AES-128-GCM and 32 bytes AES-256-GCM. */
    private static final int AES128_KEY_BYTES = 16;
    private static final int AES256_KEY_BYTES = 32;

    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    /** The P-256 field width: the byte length of x, y and d in every JWK on this curve. */
    private static final int FIELD_BYTES = 32;

    /** The uncompressed SEC 1 form of a P-256 public point: 0x04, then two 32-byte coordinates. */
    private static final int POINT_BYTES = 1 + 2 * FIELD_BYTES;

    /** HMAC-SHA256's output width, which is also HKDF's default salt width. */
    private static final int HASH_LEN = 32;

    /** `hkdf-sha256` derives from one octet up to the 255 SHA-256 blocks RFC 5869 counts. */
    private static final int HKDF_MIN_OCTETS = 1;
    private static final int HKDF_MAX_OCTETS = 8160;

    /**
     * RSA-OAEP over SHA-256 with SHA-256 as the MGF1 hash, explicit on both ends. The transform
     * string alone leaves the JDK defaulting MGF1 to SHA-1 (JDK-8058549), which agrees with
     * itself and with no other runtime; WebCrypto and Go both use SHA-256 for MGF1.
     */
    private static final String RSA_OAEP_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final OAEPParameterSpec RSA_OAEP_PARAMS =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    /** secp256r1, the curve `ecdh-p256` agrees on and `p256-point` encodes. */
    private static final ECParameterSpec P256 = p256Params();

    private static ECParameterSpec p256Params() {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec("secp256r1"));
            return ap.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("no secp256r1 parameters on this JDK", e);
        }
    }

    private Bridge() {
    }

    /** A batch or a request this bridge cannot serve, which is never a refusal. */
    private static final class BridgeFault extends RuntimeException {

        private static final long serialVersionUID = 1L;

        BridgeFault(String message) {
            super(message);
        }
    }

    /**
     * One observation, which in this contract is always one member carrying one
     * string: `bytesHex`, `okmBase64url`, `plaintextBase64url`,
     * `ciphertextBase64url`, `sharedSecretBase64url`, `pointBase64url` or
     * `refused`. The contract defines no observation carrying two members, so
     * this type can hold only one member.
     */
    private record Observation(String member, String value) {
    }

    private record Result(String id, String op, Observation observation) {
    }

    /** A decoded base64url value, or the reason the spelling is not canonical. */
    private record Decoded(byte[] bytes, String problem) {

        static Decoded of(byte[] bytes) {
            return new Decoded(bytes, null);
        }

        static Decoded refused(String problem) {
            return new Decoded(null, problem);
        }

        boolean ok() {
            return problem == null;
        }
    }

    public static void main(String[] args) {
        PrintStream err = System.err;
        String raw;
        try {
            raw = readAll(System.in);
        } catch (IOException e) {
            err.println("bridge: stdin could not be read: " + e.getMessage());
            System.exit(1);
            return;
        }

        List<Result> results;
        try {
            results = answerBatch(raw, err);
        } catch (BridgeFault fault) {
            err.println("bridge: " + fault.getMessage());
            System.exit(1);
            return;
        } catch (RuntimeException error) {
            err.println("bridge: " + error.getClass().getName() + ": " + error.getMessage());
            System.exit(1);
            return;
        }

        // Written as bytes and flushed here rather than left to exit. A
        // PrintStream's buffer is not promised to reach the file descriptor on
        // System.exit, and a bridge whose last kilobyte is dropped writes half a
        // JSON value, which the runner reads as a lane that cannot write the
        // protocol rather than as an answer it lost.
        byte[] out = (encodeBatch(results) + "\n").getBytes(StandardCharsets.UTF_8);
        System.out.write(out, 0, out.length);
        System.out.flush();
        if (System.out.checkError()) {
            err.println("bridge: the result could not be written to stdout.");
            System.exit(1);
            return;
        }
        System.exit(0);
    }

    private static String readAll(InputStream in) throws IOException {
        return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * The request envelope, read strictly, and one result per request in request order.
     *
     * Order is irrelevant to the runner, which keys results by the (id, op) pair, so
     * request order is kept only because it makes a hand-read batch easy to follow.
     */
    private static List<Result> answerBatch(String raw, PrintStream err) {
        Json.OMap batch;
        try {
            batch = Json.parse(raw);
        } catch (Json.JsonException e) {
            throw new BridgeFault("the batch on stdin is not readable JSON: " + e.getMessage());
        }
        closedMembers(batch, List.of("protocol", "requests"), "the batch");
        if (!BATCH_PROTOCOL.equals(batch.raw("protocol"))) {
            throw new BridgeFault("the batch names a protocol this bridge does not speak.");
        }
        List<Object> requests = batch.list("requests");
        if (requests == null) {
            throw new BridgeFault("the batch carries no requests array.");
        }

        List<Result> results = new ArrayList<>();
        for (Object entry : requests) {
            if (!(entry instanceof Json.OMap request)) {
                throw new BridgeFault("a request entry is not a JSON object.");
            }
            closedMembers(request, List.of("id", "op", "input"), "a request entry");
            String id = request.str("id");
            if (id.isEmpty()) {
                throw new BridgeFault("a request entry carries no id.");
            }
            if (!(request.raw("op") instanceof String op)) {
                throw new BridgeFault("request " + id + " carries no op.");
            }
            Json.OMap input = request.obj("input");
            if (input == null) {
                throw new BridgeFault("request " + id + " carries no input object.");
            }
            results.add(new Result(id, op, observe(op, input, id, err)));
        }
        return results;
    }

    /** One observation for one request, or a fault if the operation is not one of the seven. */
    private static Observation observe(String op, Json.OMap input, String id, PrintStream err) {
        switch (op) {
            case "decode-base64url":
                return observeDecodeBase64url(input, id, err);
            case "hkdf-sha256":
                return observeHkdfSha256(input, id);
            case "open-aes-gcm":
                return observeOpenAesGcm(input, id, err);
            case "seal-aes-gcm":
                return observeSealAesGcm(input, id);
            case "ecdh-p256":
                return observeEcdhP256(input, id);
            case "p256-point":
                return observeP256Point(input, id);
            case "open-rsa-oaep":
                return observeOpenRsaOaep(input, id, err);
            default:
                throw new BridgeFault("request " + id + " names operation " + op
                        + ", which this bridge does not implement.");
        }
    }

    /**
     * The strict field spelling: RFC 4648 section 5 alphabet, no padding, a
     * length that encodes a whole byte count, and zero unused trailing bits.
     *
     * Which of those rules fired goes to stderr. The observation carries the one
     * closed code, because the contract has one.
     */
    private static Observation observeDecodeBase64url(Json.OMap input, String id, PrintStream err) {
        closedMembers(input, List.of("value"), "the input of request " + id);
        Decoded decoded = decodeStrictBase64url(requiredString(input, "value", id));
        if (!decoded.ok()) {
            err.println("bridge: " + id + " refused a value: " + decoded.problem());
            return new Observation("refused", "invalid_base64url");
        }
        return new Observation("bytesHex", hex(decoded.bytes()));
    }

    /**
     * This bridge runs one HKDF-SHA-256 derivation, with an empty salt, over the
     * octets its request carries.
     *
     * A request carries key material, info octets and an output width, and this
     * bridge reads all three as bytes and a count. Both base64url members go
     * through the strict reader above, so the derivation runs over the `info`
     * octets themselves: the recorded values carry 0x00 and octets above 0x7f,
     * and a text type would rewrite those. A member that does not decode, and a
     * `length` outside 1 through 8160, leave this bridge unable to serve the
     * request.
     */
    private static Observation observeHkdfSha256(Json.OMap input, String id) {
        closedMembers(input, List.of("ikmBase64url", "infoBase64url", "length"), "the input of request " + id);
        byte[] ikm = carrierBytes(input, "ikmBase64url", id);
        byte[] info = carrierBytes(input, "infoBase64url", id);
        long length = requiredInteger(input, "length", id);
        if (length < HKDF_MIN_OCTETS || length > HKDF_MAX_OCTETS) {
            throw new BridgeFault("request " + id + " asks for " + length + " HKDF octets, and this operation "
                    + "derives " + HKDF_MIN_OCTETS + " through " + HKDF_MAX_OCTETS + ".");
        }
        return new Observation("okmBase64url",
                BASE64URL_ENCODER.encodeToString(hkdfSha256(ikm, info, (int) length)));
    }

    /**
     * AES-GCM over one `ciphertext || tag` carrier, which is the layout the JCA
     * takes in one buffer.
     *
     * The key's width picks the cipher: 16 bytes AES-128-GCM and 32 bytes
     * AES-256-GCM. Any other key width, and a nonce that is not 12 bytes, leave
     * the bridge unable to serve the request. A carrier shorter than the tag is
     * `authentication_failed`: the JCA throws AEADBadTagException for it, reporting
     * a tag that did not verify, and there is no shorter carrier whose tag
     * could.
     */
    private static Observation observeOpenAesGcm(Json.OMap input, String id, PrintStream err) {
        closedMembers(
                input,
                List.of("keyBase64url", "nonceBase64url", "ciphertextBase64url", "aadBase64url"),
                "the input of request " + id);
        byte[] key = aesKey(input, id);
        byte[] nonce = gcmNonce(input, id);
        byte[] carrier = carrierBytes(input, "ciphertextBase64url", id);
        byte[] aad = carrierBytes(input, "aadBase64url", id);

        byte[] plaintext;
        try {
            plaintext = gcmOpen(key, nonce, carrier, aad);
        } catch (AEADBadTagException e) {
            // The JCA reports the wrong key, another AAD, a flipped byte and a carrier with no
            // room for a tag all as one tag failure, and the contract
            // gives them one code: a tag check has no finer observable cause.
            err.println("bridge: " + id + " did not authenticate: " + e.getMessage());
            return new Observation("refused", "authentication_failed");
        } catch (GeneralSecurityException e) {
            throw new BridgeFault("request " + id + " could not be opened by this JDK: "
                    + e.getClass().getName() + ": " + e.getMessage());
        }
        return new Observation("plaintextBase64url", BASE64URL_ENCODER.encodeToString(plaintext));
    }

    /**
     * AES-GCM over one plaintext under the nonce the request names, answering
     * `ciphertext || tag` in one buffer, which is what the JCA hands back.
     *
     * The key's width picks the cipher the same way {@link #observeOpenAesGcm}
     * reads it. This operation defines no refusal: a key or nonce of another
     * width, and a seal this JDK declines, are requests the bridge cannot serve.
     */
    private static Observation observeSealAesGcm(Json.OMap input, String id) {
        closedMembers(
                input,
                List.of("keyBase64url", "nonceBase64url", "plaintextBase64url", "aadBase64url"),
                "the input of request " + id);
        byte[] key = aesKey(input, id);
        byte[] nonce = gcmNonce(input, id);
        byte[] plaintext = carrierBytes(input, "plaintextBase64url", id);
        byte[] aad = carrierBytes(input, "aadBase64url", id);

        byte[] carrier;
        try {
            carrier = gcmSeal(key, nonce, plaintext, aad);
        } catch (GeneralSecurityException e) {
            throw new BridgeFault("request " + id + " could not be sealed by this JDK: "
                    + e.getClass().getName() + ": " + e.getMessage());
        }
        return new Observation("ciphertextBase64url", BASE64URL_ENCODER.encodeToString(carrier));
    }

    /**
     * One ECDH agreement over P-256: import the private JWK and the peer's
     * 65-byte uncompressed point through the JDK's own key routines, then run
     * `KeyAgreement("ECDH")` once and answer the agreed x-coordinate at the full
     * field width.
     *
     * This operation defines no refusal. A peer point this JDK declines to
     * import, and an agreement it declines to make, are requests the bridge
     * cannot serve. No KDF runs over the secret.
     */
    private static Observation observeEcdhP256(Json.OMap input, String id) {
        closedMembers(input, List.of("privateKeyJwk", "peerPointBase64url"), "the input of request " + id);

        PrivateKey privateKey = requireP256Private(input, "privateKeyJwk", id);
        byte[] point = carrierBytes(input, "peerPointBase64url", id);

        byte[] shared;
        try {
            PublicKey peer = p256PublicFromPoint(point);
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(privateKey);
            agreement.doPhase(peer, true);
            shared = agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new BridgeFault("request " + id + " could not be agreed on this JDK: "
                    + e.getClass().getName() + ": " + e.getMessage());
        }
        return new Observation("sharedSecretBase64url", BASE64URL_ENCODER.encodeToString(fieldWidth(shared, id)));
    }

    /**
     * One P-256 public JWK as the 65-byte uncompressed SEC 1 point: 0x04, then
     * `x` and `y`, each at the full field width, so a coordinate that starts
     * with a zero byte keeps it.
     *
     * The coordinates come straight off the JWK, which RFC 7518 already fixes at
     * 32 bytes each. This operation defines no refusal.
     */
    private static Observation observeP256Point(Json.OMap input, String id) {
        closedMembers(input, List.of("publicKeyJwk"), "the input of request " + id);

        Json.OMap jwk = requiredObject(input, "publicKeyJwk", id);
        checkEcJwk(jwk, id, "publicKeyJwk");
        byte[] x = jwkFieldElement(jwk, "x", id, "publicKeyJwk");
        byte[] y = jwkFieldElement(jwk, "y", id, "publicKeyJwk");

        byte[] point = new byte[POINT_BYTES];
        point[0] = 0x04;
        System.arraycopy(x, 0, point, 1, FIELD_BYTES);
        System.arraycopy(y, 0, point, 1 + FIELD_BYTES, FIELD_BYTES);
        return new Observation("pointBase64url", BASE64URL_ENCODER.encodeToString(point));
    }

    /**
     * Opens one RSA-OAEP-SHA256 ciphertext to the whole plaintext, one modulus
     * wide, whatever it holds.
     *
     * A wrong private key, a ciphertext that is not one modulus wide and a
     * flipped byte are one `unseal_failed`: OAEP's own padding check does not
     * tell them apart, and neither does this.
     */
    private static Observation observeOpenRsaOaep(Json.OMap input, String id, PrintStream err) {
        closedMembers(input, List.of("ciphertextBase64url", "privateKeyJwk"), "the input of request " + id);

        PrivateKey privateKey = requireRsaPrivate(input, "privateKeyJwk", id);
        byte[] ciphertext = carrierBytes(input, "ciphertextBase64url", id);

        byte[] plaintext;
        try {
            Cipher cipher = Cipher.getInstance(RSA_OAEP_TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, RSA_OAEP_PARAMS);
            plaintext = cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            err.println("bridge: " + id + " did not open: " + e.getClass().getName() + ": " + e.getMessage());
            return new Observation("refused", "unseal_failed");
        }
        return new Observation("plaintextBase64url", BASE64URL_ENCODER.encodeToString(plaintext));
    }

    // ---- AES-GCM ------------------------------------------------------------
    //
    // Both AES-GCM operations read their key and nonce the same way and call the
    // same two Cipher wrappers, so the two operations differ only in the
    // direction they run and the member they answer with.

    /** The key of an AES-GCM request, 16 bytes for AES-128-GCM or 32 for AES-256-GCM. */
    private static byte[] aesKey(Json.OMap input, String id) {
        byte[] key = carrierBytes(input, "keyBase64url", id);
        if (key.length != AES128_KEY_BYTES && key.length != AES256_KEY_BYTES) {
            throw new BridgeFault("request " + id + " carries a " + key.length
                    + "-byte key, and AES-GCM here takes " + AES128_KEY_BYTES + " or "
                    + AES256_KEY_BYTES + " bytes.");
        }
        return key;
    }

    /** The nonce of an AES-GCM request, which the contract fixes at 12 bytes. */
    private static byte[] gcmNonce(Json.OMap input, String id) {
        byte[] nonce = carrierBytes(input, "nonceBase64url", id);
        if (nonce.length != GCM_NONCE_BYTES) {
            throw new BridgeFault("request " + id + " carries a " + nonce.length
                    + "-byte nonce, and the contract fixes it at " + GCM_NONCE_BYTES + " bytes.");
        }
        return nonce;
    }

    private static byte[] gcmSeal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        addAad(cipher, aad);
        return cipher.doFinal(plaintext);
    }

    private static byte[] gcmOpen(byte[] key, byte[] nonce, byte[] carrier, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        addAad(cipher, aad);
        return cipher.doFinal(carrier);
    }

    /**
     * Additional data, passed only when the request carries some. The JCA
     * authenticates zero octets either way, so this bridge skips the call and an
     * empty AAD takes the same path an absent one takes.
     */
    private static void addAad(Cipher cipher, byte[] aad) {
        if (aad.length > 0) {
            cipher.updateAAD(aad);
        }
    }

    // ---- P-256 keys ---------------------------------------------------------
    //
    // Every coordinate goes through BigInteger's sign-aware constructor: without
    // the sign argument a coordinate whose top bit is set becomes negative.

    /** One P-256 private JWK, imported through KeyFactory, or a request this bridge cannot serve. */
    private static PrivateKey requireP256Private(Json.OMap input, String member, String id) {
        Json.OMap jwk = requiredObject(input, member, id);
        checkEcJwk(jwk, id, member);
        byte[] d = jwkFieldElement(jwk, "d", id, member);
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, d), P256));
        } catch (GeneralSecurityException e) {
            throw new BridgeFault("request " + id + " carries a " + member + " this bridge cannot import: "
                    + e.getMessage() + ".");
        }
    }

    private static void checkEcJwk(Json.OMap jwk, String id, String member) {
        if (!(jwk.raw("kty") instanceof String kty) || !kty.equals("EC")
                || !(jwk.raw("crv") instanceof String crv) || !crv.equals("P-256")) {
            throw new BridgeFault("request " + id + "'s " + member + " is not an EC P-256 JWK.");
        }
    }

    /**
     * A public key from an uncompressed point, which is how a peer's public half
     * arrives. The width and the leading 0x04 are checked here; the curve is
     * not, so an off-curve point imports cleanly and the key agreement below
     * declines it.
     */
    private static PublicKey p256PublicFromPoint(byte[] point) throws GeneralSecurityException {
        if (point.length != POINT_BYTES || point[0] != 0x04) {
            throw new InvalidKeyException("a P-256 point here is " + POINT_BYTES
                    + " bytes starting 0x04, uncompressed");
        }
        byte[] x = Arrays.copyOfRange(point, 1, 1 + FIELD_BYTES);
        byte[] y = Arrays.copyOfRange(point, 1 + FIELD_BYTES, POINT_BYTES);
        return KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), P256));
    }

    /**
     * One agreed secret at the P-256 field width. SunEC hands back 32 bytes with
     * their leading zero bytes in place. A provider that trims one hands back a
     * shorter value, and this method puts the leading zero bytes back; a longer
     * value leaves the bridge unable to serve the request.
     */
    private static byte[] fieldWidth(byte[] secret, String id) {
        if (secret.length == FIELD_BYTES) {
            return secret;
        }
        if (secret.length > FIELD_BYTES) {
            throw new BridgeFault("request " + id + " agreed a " + secret.length
                    + "-byte secret, and a P-256 secret is " + FIELD_BYTES + " bytes.");
        }
        byte[] padded = new byte[FIELD_BYTES];
        System.arraycopy(secret, 0, padded, FIELD_BYTES - secret.length, secret.length);
        return padded;
    }

    // ---- HKDF-SHA256, hand rolled --------------------------------------------
    //
    // JDK 21 has no javax.crypto.KDF and no HKDF service in any bundled
    // provider, so RFC 5869 is written out here over Mac. An absent salt would
    // be a zero-length HmacSHA256 key, and SecretKeySpec throws outright on one,
    // so extract's empty salt widens to 32 zero bytes here, which is what RFC
    // 5869 and WebCrypto both mean by "no salt".

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[HASH_LEN] : key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable on this JDK", e);
        }
    }

    /**
     * RFC 5869 over HMAC-SHA-256 with an empty salt: extract once, then expand
     * to as many octets as the caller asks for.
     *
     * `info` arrives as octets, so a recorded value carrying 0x00 or an octet
     * above 0x7f reaches the HMAC unchanged. The counter loop runs once up to 32
     * octets and once more for each block beyond that.
     */
    private static byte[] hkdfSha256(byte[] ikm, byte[] info, int length) {
        byte[] prk = hmacSha256(new byte[0], ikm);
        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int written = 0;
        for (int counter = 1; written < length; counter++) {
            byte[] block = new byte[previous.length + info.length + 1];
            System.arraycopy(previous, 0, block, 0, previous.length);
            System.arraycopy(info, 0, block, previous.length, info.length);
            block[block.length - 1] = (byte) counter;
            previous = hmacSha256(prk, block);
            int take = Math.min(previous.length, length - written);
            System.arraycopy(previous, 0, out, written, take);
            written += take;
        }
        return out;
    }

    // ---- RSA, for open-rsa-oaep -----------------------------------------------

    /**
     * One RSA private JWK: `n`, `e`, `d`, `p`, `q`, `dp`, `dq` and `qi`, all eight
     * required. The JCA's `RSAPrivateCrtKeySpec` has no equivalent to Go's
     * `Precompute()`, so a JWK short of a CRT member is a request this bridge
     * cannot serve rather than one rebuilt from `n` and `d` alone.
     */
    private static PrivateKey requireRsaPrivate(Json.OMap input, String member, String id) {
        Json.OMap jwk = requiredObject(input, member, id);
        if (!(jwk.raw("kty") instanceof String kty) || !kty.equals("RSA")) {
            throw new BridgeFault("request " + id + "'s " + member + " is not an RSA JWK.");
        }
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(
                    jwkInt(jwk, "n", id, member), jwkInt(jwk, "e", id, member), jwkInt(jwk, "d", id, member),
                    jwkInt(jwk, "p", id, member), jwkInt(jwk, "q", id, member),
                    jwkInt(jwk, "dp", id, member), jwkInt(jwk, "dq", id, member), jwkInt(jwk, "qi", id, member)));
        } catch (GeneralSecurityException e) {
            throw new BridgeFault("request " + id + " carries a " + member + " this bridge cannot import: "
                    + e.getMessage() + ".");
        }
    }

    private static BigInteger jwkInt(Json.OMap jwk, String member, String id, String jwkMember) {
        if (!(jwk.raw(member) instanceof String value)) {
            throw new BridgeFault("request " + id + "'s " + jwkMember + " carries no string " + member + ".");
        }
        byte[] bytes;
        try {
            bytes = BASE64URL_DECODER.decode(value);
        } catch (IllegalArgumentException e) {
            throw new BridgeFault("request " + id + "'s " + jwkMember + " has a " + member
                    + " this bridge cannot decode.");
        }
        if (bytes.length == 0) {
            throw new BridgeFault("request " + id + "'s " + jwkMember + " carries an empty " + member + ".");
        }
        return new BigInteger(1, bytes);
    }

    /**
     * One JWK member at the exact P-256 field width. RFC 7518 § 6.2.1.2 fixes
     * `x`, `y` and `d` at 32 bytes, left zero padded, and this is read at that
     * exact width rather than widened, the same way a short one would fail a
     * WebCrypto import.
     */
    private static byte[] jwkFieldElement(Json.OMap jwk, String member, String id, String jwkMember) {
        if (!(jwk.raw(member) instanceof String value)) {
            throw new BridgeFault("request " + id + "'s " + jwkMember + " carries no string " + member + ".");
        }
        byte[] bytes;
        try {
            bytes = BASE64URL_DECODER.decode(value);
        } catch (IllegalArgumentException e) {
            throw new BridgeFault("request " + id + "'s " + jwkMember + " has a " + member
                    + " this bridge cannot decode.");
        }
        if (bytes.length != FIELD_BYTES) {
            throw new BridgeFault("request " + id + "'s " + jwkMember + " has a " + member + " that is "
                    + bytes.length + " bytes, and a P-256 " + member + " is exactly " + FIELD_BYTES + ".");
        }
        return bytes;
    }

    /**
     * One JSON object holding exactly the named members, or a request this bridge
     * cannot serve.
     *
     * The contract calls the envelope, the request row and every input closed, and
     * this method checks that they are. A member outside
     * the set means the sender is writing a protocol this bridge has not agreed
     * to, and a missing one means it left out something the operation is defined
     * by.
     */
    private static void closedMembers(Json.OMap object, List<String> members, String what) {
        Set<String> present = new LinkedHashSet<>(object.keys());
        Set<String> named = new LinkedHashSet<>(members);
        if (!present.equals(named)) {
            throw new BridgeFault(what + " carries {" + String.join(", ", present)
                    + "}, and it carries {" + String.join(", ", named) + "} exactly.");
        }
    }

    /** One input member that must be present and a string, or a request this bridge cannot serve. */
    private static String requiredString(Json.OMap input, String member, String id) {
        if (!(input.raw(member) instanceof String value)) {
            throw new BridgeFault("request " + id + " carries no string " + member + ".");
        }
        return value;
    }

    /**
     * One input member that must be present and integral, or a request this
     * bridge cannot serve.
     *
     * {@link Json} hands back a Long for an integral number and a Double for
     * everything else numeric, so a fractional count fails the type test here.
     */
    private static long requiredInteger(Json.OMap input, String member, String id) {
        if (!(input.raw(member) instanceof Long value)) {
            throw new BridgeFault("request " + id + " carries no integer " + member + ".");
        }
        return value;
    }

    /** One input member that must be present and a JSON object, or a request this bridge cannot serve. */
    private static Json.OMap requiredObject(Json.OMap input, String member, String id) {
        Json.OMap value = input.obj(member);
        if (value == null) {
            throw new BridgeFault("request " + id + " carries no " + member + " object.");
        }
        return value;
    }

    /** One base64url input member decoded to raw bytes. Every carrier literal is canonical. */
    private static byte[] carrierBytes(Json.OMap input, String member, String id) {
        Decoded decoded = decodeStrictBase64url(requiredString(input, member, id));
        if (!decoded.ok()) {
            throw new BridgeFault("request " + id + " carries a " + member
                    + " this bridge cannot decode: " + decoded.problem() + ".");
        }
        return decoded.bytes();
    }

    /**
     * Canonical unpadded base64url to bytes, or the reason the spelling is not
     * canonical.
     *
     * The four rules are the contract's, and three of them are here because the
     * JDK does not apply them. Base64.getUrlDecoder() rejects `+`, `/` and
     * whitespace and that is the whole of its strictness: it accepts `=` padding,
     * so `3q2-7w==` decodes there, and it accepts non-zero unused trailing bits,
     * so `3q2-7w` and `3q2-7x` decode to the same four bytes. The alphabet test
     * covers padding, and the decode-and-re-encode comparison covers the trailing
     * bits.
     */
    private static Decoded decodeStrictBase64url(String value) {
        if (value.isEmpty()) {
            return Decoded.of(new byte[0]);
        }
        if (!BASE64URL_ALPHABET.matcher(value).matches()) {
            return Decoded.refused("a character outside the base64url alphabet, which includes padding");
        }
        if (value.length() % 4 == 1) {
            return Decoded.refused("a length that encodes no whole byte count");
        }

        byte[] bytes;
        try {
            bytes = BASE64URL_DECODER.decode(value);
        } catch (IllegalArgumentException e) {
            return Decoded.refused("bytes the decoder would not read: " + e.getMessage());
        }
        if (!BASE64URL_ENCODER.encodeToString(bytes).equals(value)) {
            return Decoded.refused("unused trailing bits: the value does not re-encode to itself");
        }
        return Decoded.of(bytes);
    }

    /** Raw bytes as lowercase hexadecimal, two digits per byte, no separator and no prefix. */
    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format(Locale.ROOT, "%02x", b));
        }
        return out.toString();
    }

    // ---- writing the answer ------------------------------------------------
    //
    // The document written here is one envelope holding one array of
    // three-member rows, so it is built by hand rather than modelled. The pinned
    // Jackson on the classpath could write it, and it would write other bytes:
    // measured on 2.22.2, its generator escapes a lone surrogate as \uD800 with
    // uppercase hex and writes every other non-ASCII character through as UTF-8,
    // where jsonString below escapes everything above `~` with lowercase hex. The
    // runner compares strings rather than bytes, so either spelling is read the
    // same, and this lane keeps the spelling it has produced since it landed.
    // Escaping is decided in one place: every
    // string goes through jsonString, because ids and ops are the sender's bytes
    // and a value carrying a quote would otherwise write a document nobody can
    // read.

    private static String encodeBatch(List<Result> results) {
        StringBuilder out = new StringBuilder();
        out.append("{\"protocol\":").append(jsonString(BATCH_PROTOCOL)).append(",\"results\":[");
        for (int i = 0; i < results.size(); i++) {
            Result result = results.get(i);
            if (i > 0) {
                out.append(',');
            }
            out.append("{\"id\":").append(jsonString(result.id()))
                    .append(",\"op\":").append(jsonString(result.op()))
                    .append(",\"observation\":{").append(jsonString(result.observation().member()))
                    .append(':').append(jsonString(result.observation().value()))
                    .append("}}");
        }
        return out.append("]}").toString();
    }

    /**
     * One JSON string, ASCII only.
     *
     * Everything above `~` is escaped as `\\uXXXX` rather than written through.
     * Java strings are UTF-16 and a lone surrogate in one, which the parser keeps
     * as written, turns into a replacement character on the way to UTF-8 bytes:
     * escaping instead carries the code unit the sender wrote, and the reader
     * decodes the identical string either way.
     */
    private static String jsonString(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }
}
