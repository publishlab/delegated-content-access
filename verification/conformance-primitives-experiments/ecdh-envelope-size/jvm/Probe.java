// JVM probe. Reads `_shared/fixture.json` inputs, seals and opens the three
// envelope profiles through JCE, and writes observations as JSON on stdout. It
// reads no expectation and assigns no verdict.

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Probe {
    private static final int TAG_BYTES = 16;

    // The SubjectPublicKeyInfo shell for a 65-byte P-256 point: id-ecPublicKey
    // with prime256v1, then a BIT STRING holding the point. JCE has no raw-point
    // entry, so every point import here is container-assisted.
    private static final String SPKI_65 = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    private static Map<String, Object> inputs;
    private static String compressedImport = "unsupported";
    private static String compressedImportRefusal = "";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> at(Map<String, Object> node, String key) {
        return (Map<String, Object>) node.get(key);
    }

    private static String text(Map<String, Object> node, String key) {
        return (String) node.get(key);
    }

    private static int count(Map<String, Object> node, String key) {
        return (int) (long) (Long) node.get(key);
    }

    private static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] raw) {
        StringBuilder out = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }

    private static String b64url(byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private static byte[] join(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, at, part.length);
            at += part.length;
        }
        return out;
    }

    private static PublicKey importPointSpki(byte[] point) throws Exception {
        byte[] der = join(unhex(SPKI_65), point);
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    // SunEC reads the uncompressed encoding only, through either entry, so a
    // 33-byte point is recovered by the decoder in Decompress.java first and the
    // recovered 65 bytes then go through the same container-assisted import. The
    // library still validates the point: the decoder only reverses the encoding.
    private static PublicKey importPoint(byte[] point) throws Exception {
        return importPointSpki(point.length == 33 ? Decompress.uncompressed(point) : point);
    }

    // Whether the decoder and the import behind it read the fixture's compressed
    // point at all. The unsupported answer is left for the runtime whose
    // uncompressed import refuses the recovered point too.
    private static void detectCompressedImport() {
        try {
            importPoint(unhex(text(at(inputs, "ephemeral"), "publicCompressedHex")));
            compressedImport = "decoder, then container-assisted";
        } catch (Exception closed) {
            compressedImport = "unsupported";
            compressedImportRefusal = closed.getMessage() == null ? closed.toString() : closed.getMessage();
        }
    }

    private static PrivateKey importPrivate(String pkcs8Hex) throws Exception {
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(unhex(pkcs8Hex)));
    }

    /** The 32-byte fixed-width x-coordinate, or null when import or agreement fails. */
    private static byte[] agree(byte[] point, String pkcs8Hex) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(importPrivate(pkcs8Hex));
            agreement.doPhase(importPoint(point), true);
            return agreement.generateSecret();
        } catch (Exception closed) {
            return null;
        }
    }

    // HKDF-SHA256, extract and expand, over the JDK's HMAC. An empty salt and a
    // salt of one hash length of zero bytes are the same input to extract, and
    // Mac refuses a zero-length key, so the probe passes the zero block.
    private static byte[] hkdf(byte[] secret, String info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(secret);

        byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[length];
        byte[] block = new byte[0];
        int filled = 0;
        for (int counter = 1; filled < length; counter++) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(block);
            mac.update(infoBytes);
            mac.update((byte) counter);
            block = mac.doFinal();
            int take = Math.min(block.length, length - filled);
            System.arraycopy(block, 0, out, filled, take);
            filled += take;
        }
        return out;
    }

    private static byte[] gcm(int mode, byte[] key, byte[] nonce, byte[] payload, String aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BYTES * 8, nonce));
        cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(payload);
    }

    private static byte[] gcmOpen(byte[] key, byte[] nonce, byte[] carrier, String aad) {
        try {
            return gcm(Cipher.DECRYPT_MODE, key, nonce, carrier, aad);
        } catch (Exception closed) {
            return null;
        }
    }

    // One profile switch, shared by the three shapes: how wide the carried point
    // is, and whether the key and nonce come from the fixture or from HKDF.
    private record Shape(String name, String pointKey, boolean derived) {
        int pointBytes() {
            return name.equals("hkdf-compressed-65") ? 33 : 65;
        }
    }

    private static final Shape[] PROFILES = {
        new Shape("control-109", "publicUncompressedHex", false),
        new Shape("hkdf-97", "publicUncompressedHex", true),
        new Shape("hkdf-compressed-65", "publicCompressedHex", true),
    };

    private static byte[][] material(Shape shape, byte[] shared, String bind) throws Exception {
        if (shared == null) {
            return null;
        }
        if (!shape.derived()) {
            return new byte[][] { shared, unhex(text(inputs, "controlNonceHex")) };
        }
        Map<String, Object> hkdf = at(inputs, "hkdf");
        return new byte[][] {
            hkdf(shared, text(hkdf, "keyInfoPrefix") + bind, count(hkdf, "keyBytes")),
            hkdf(shared, text(hkdf, "nonceInfoPrefix") + bind, count(hkdf, "nonceBytes")),
        };
    }

    // The publisher side agrees with the issuer public point under the fixed
    // ephemeral private key, so every runtime seals the same bytes.
    private static byte[][] sealingMaterial(Shape shape, String bind) throws Exception {
        byte[] shared = agree(
            unhex(text(at(inputs, "issuer"), "publicUncompressedHex")),
            text(at(inputs, "ephemeral"), "privatePkcs8Hex"));
        return material(shape, shared, bind);
    }

    private static byte[] openEnvelope(Shape shape, byte[] envelope, String bind) throws Exception {
        int width = shape.pointBytes();
        if (envelope.length < width) {
            return null;
        }
        byte[] point = java.util.Arrays.copyOfRange(envelope, 0, width);
        byte[] rest = java.util.Arrays.copyOfRange(envelope, width, envelope.length);
        byte[][] pair = material(shape, agree(point, text(at(inputs, "issuer"), "privatePkcs8Hex")), bind);
        if (pair == null) {
            return null;
        }
        if (shape.derived()) {
            return gcmOpen(pair[0], pair[1], rest, bind);
        }
        return gcmOpen(
            pair[0],
            java.util.Arrays.copyOfRange(rest, 0, 12),
            java.util.Arrays.copyOfRange(rest, 12, rest.length),
            bind);
    }

    // The probe answers every negative case with one word. The experiment is looking
    // for a released key, so the probe says which of the two happened
    // and nothing about the cause.
    private static String releases(Shape shape, byte[] envelope, String bind) throws Exception {
        byte[] opened = openEnvelope(shape, envelope, bind);
        return opened != null && opened.length > 0 ? "key-released" : "no-key";
    }

    private static Map<String, Object> runProfile(Shape shape) throws Exception {
        String bind = text(at(inputs, "bind"), "value");
        byte[] point = unhex(text(at(inputs, "ephemeral"), shape.pointKey()));

        Map<String, Object> out = new LinkedHashMap<>();
        if (point.length == 33 && compressedImport.equals("unsupported")) {
            out.put("status", "unsupported");
            out.put("reason", "no compressed-point import through the runtime: " + compressedImportRefusal);
            return out;
        }

        byte[][] sealing = sealingMaterial(shape, bind);
        byte[] key = sealing[0];
        byte[] nonce = sealing[1];
        byte[] carrier = gcm(Cipher.ENCRYPT_MODE, key, nonce, unhex(text(inputs, "dcaKeyHex")), bind);
        byte[] envelope = shape.derived() ? join(point, carrier) : join(point, nonce, carrier);

        byte[] flipped = envelope.clone();
        flipped[flipped.length - TAG_BYTES - 1] ^= 0x01;

        Map<String, Object> offCurvePoints = at(inputs, "offCurvePoints");
        byte[] badPoint = unhex(text(offCurvePoints, point.length == 33 ? "compressedHex" : "uncompressedHex"));
        byte[] offCurve = join(badPoint, java.util.Arrays.copyOfRange(envelope, point.length, envelope.length));

        // A compressed x below p whose curve equation has no square root mod p.
        // Only a 33-byte point carries that case, so the probe reports `n/a` for the wider profiles.
        String nonResiduePoint = "n/a";
        if (point.length == 33) {
            byte[] carried = unhex(text(offCurvePoints, "compressedNonResidueHex"));
            nonResiduePoint = releases(
                shape,
                join(carried, java.util.Arrays.copyOfRange(envelope, point.length, envelope.length)),
                bind);
        }

        byte[] opened = openEnvelope(shape, envelope, bind);

        out.put("status", "answered");
        out.put("envelopeHex", hex(envelope));
        out.put("derivedKeyHex", hex(key));
        out.put("derivedNonceHex", hex(nonce));
        out.put("envelopeBase64url", b64url(envelope));
        out.put("decodedBytes", envelope.length);
        out.put("base64urlChars", b64url(envelope).length());
        out.put("pointBytes", point.length);
        out.put("openedKeyHex", opened == null ? "open-failed" : hex(opened));
        out.put("wrongBind", releases(shape, envelope, text(at(inputs, "otherBind"), "value")));
        out.put("flippedCiphertext", releases(shape, flipped, bind));
        out.put("invalidPoint", releases(shape, offCurve, bind));
        out.put("nonResiduePoint", nonResiduePoint);
        return out;
    }

    private static Map<String, Object> derivedPair(String pkcs8Hex, String bind) throws Exception {
        byte[] shared = agree(unhex(text(at(inputs, "issuer"), "publicUncompressedHex")), pkcs8Hex);
        Map<String, Object> hkdf = at(inputs, "hkdf");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("keyHex", hex(hkdf(shared, text(hkdf, "keyInfoPrefix") + bind, count(hkdf, "keyBytes"))));
        out.put("nonceHex", hex(hkdf(shared, text(hkdf, "nonceInfoPrefix") + bind, count(hkdf, "nonceBytes"))));
        return out;
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Path source = Path.of(System.getenv().getOrDefault("DCA_EXPERIMENT_DIR", ".."));
        String raw = Files.readString(source.resolve("_shared").resolve("fixture.json"), StandardCharsets.UTF_8);
        inputs = (Map<String, Object>) ((Map<String, Object>) Json.parse(raw)).get("inputs");

        detectCompressedImport();
        String bind = text(at(inputs, "bind"), "value");

        Map<String, Object> profiles = new LinkedHashMap<>();
        for (Shape shape : PROFILES) {
            profiles.put(shape.name(), runProfile(shape));
        }

        Map<String, Object> pairs = new LinkedHashMap<>();
        String ephemeral = text(at(inputs, "ephemeral"), "privatePkcs8Hex");
        pairs.put("sameEphemeralSameBind", derivedPair(ephemeral, bind));
        pairs.put("sameEphemeralSameBindRepeat", derivedPair(ephemeral, bind));
        pairs.put("sameEphemeralOtherBind", derivedPair(ephemeral, text(at(inputs, "otherBind"), "value")));
        pairs.put("freshEphemeralSameBind",
            derivedPair(text(at(inputs, "ephemeralFresh"), "privatePkcs8Hex"), bind));

        Map<String, Object> reuse = new LinkedHashMap<>();
        for (Shape shape : PROFILES) {
            if (shape.derived()) {
                reuse.put(shape.name(), pairs);
            }
        }

        Map<String, Object> observations = new LinkedHashMap<>();
        observations.put("runtime", "jvm");
        observations.put("runtimeVersion", "Java " + System.getProperty("java.version")
            + " (" + System.getProperty("java.vm.name") + ")");
        observations.put("cryptoProvider", "JCE: " + KeyFactory.getInstance("EC").getProvider().getName()
            + " " + KeyFactory.getInstance("EC").getProvider().getVersionStr());
        observations.put("compressedPointImport", compressedImport);
        observations.put("profiles", profiles);
        observations.put("ephemeralReuse", reuse);

        System.out.println(Json.write(observations, 0));
    }
}
