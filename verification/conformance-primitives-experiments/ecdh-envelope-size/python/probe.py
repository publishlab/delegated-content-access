#!/usr/bin/env python3
"""Python probe. Reads `_shared/fixture.json` inputs, seals and opens the three
envelope profiles through the `cryptography` package, and writes observations as
JSON on stdout. It reads no expectation and assigns no verdict."""

import base64
import json
import os
import sys

import cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TAG_BYTES = 16
CURVE = ec.SECP256R1()

# The two SubjectPublicKeyInfo shells for a P-256 point: id-ecPublicKey with
# prime256v1, then a BIT STRING holding the 65-byte or 33-byte point.
SPKI_65 = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
SPKI_33 = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "..", "_shared", "fixture.json"), encoding="utf-8") as handle:
    INPUTS = json.load(handle)["inputs"]

HKDF_INPUTS = INPUTS["hkdf"]


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def import_point_raw(point):
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, point)


def import_point_spki(point):
    shell = SPKI_33 if len(point) == 33 else SPKI_65
    return serialization.load_der_public_key(shell + point)


# Compressed points go through the library's own import in both modes. Nothing
# here decompresses a point or touches field arithmetic.
COMPRESSED_IMPORT = "unsupported"
COMPRESSED_IMPORT_REFUSAL = ""


def detect_compressed_import():
    global COMPRESSED_IMPORT, COMPRESSED_IMPORT_REFUSAL
    point = bytes.fromhex(INPUTS["ephemeral"]["publicCompressedHex"])
    for mode, importer in (("native", import_point_raw), ("container-assisted", import_point_spki)):
        try:
            importer(point)
        except Exception as refusal:  # noqa: BLE001 - any failure rules out this import mode
            COMPRESSED_IMPORT_REFUSAL = str(refusal)
            continue
        COMPRESSED_IMPORT = mode
        return


def import_point(point):
    if len(point) == 65:
        return import_point_raw(point)
    if COMPRESSED_IMPORT == "native":
        return import_point_raw(point)
    if COMPRESSED_IMPORT == "container-assisted":
        return import_point_spki(point)
    raise ValueError("compressed point import is unsupported here")


def import_private(pkcs8_hex):
    return serialization.load_der_private_key(bytes.fromhex(pkcs8_hex), password=None)


def agree(point, pkcs8_hex):
    """The 32-byte fixed-width x-coordinate, or None when import or agreement fails."""
    try:
        public = import_point(point)
        return import_private(pkcs8_hex).exchange(ec.ECDH(), public)
    except Exception:  # noqa: BLE001 - an off-curve point lands here
        return None


def hkdf(secret, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"", info=info.encode("utf-8")).derive(secret)


def gcm_seal(key, nonce, plaintext, aad):
    return AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))


def gcm_open(key, nonce, carrier, aad):
    try:
        return AESGCM(key).decrypt(nonce, carrier, aad.encode("utf-8"))
    except Exception:  # noqa: BLE001 - a tag that does not verify lands here
        return None


# One profile switch, shared by the three shapes: how wide the carried point is,
# and whether the key and nonce come from the fixture or from HKDF.
PROFILES = {
    "control-109": {"point": "publicUncompressedHex", "derived": False},
    "hkdf-97": {"point": "publicUncompressedHex", "derived": True},
    "hkdf-compressed-65": {"point": "publicCompressedHex", "derived": True},
}


def material(profile, shared, bind):
    if shared is None:
        return None
    if not PROFILES[profile]["derived"]:
        return shared, bytes.fromhex(INPUTS["controlNonceHex"])
    return (
        hkdf(shared, HKDF_INPUTS["keyInfoPrefix"] + bind, HKDF_INPUTS["keyBytes"]),
        hkdf(shared, HKDF_INPUTS["nonceInfoPrefix"] + bind, HKDF_INPUTS["nonceBytes"]),
    )


def point_bytes(profile):
    return 33 if profile == "hkdf-compressed-65" else 65


# The publisher side agrees with the issuer public point under the fixed
# ephemeral private key, so every runtime seals the same bytes.
def sealing_material(profile, bind):
    shared = agree(bytes.fromhex(INPUTS["issuer"]["publicUncompressedHex"]), INPUTS["ephemeral"]["privatePkcs8Hex"])
    return material(profile, shared, bind)


def open_envelope(profile, envelope, bind):
    width = point_bytes(profile)
    point, rest = envelope[:width], envelope[width:]
    pair = material(profile, agree(point, INPUTS["issuer"]["privatePkcs8Hex"]), bind)
    if pair is None:
        return None
    key, nonce = pair
    if PROFILES[profile]["derived"]:
        return gcm_open(key, nonce, rest, bind)
    return gcm_open(key, rest[:12], rest[12:], bind)


# The probe answers every negative case with one word. The experiment is looking for a released key,
# so the probe says which of the two happened and
# nothing about the cause.
def releases(profile, envelope, bind):
    opened = open_envelope(profile, envelope, bind)
    return "key-released" if opened else "no-key"


def run_profile(profile):
    bind = INPUTS["bind"]["value"]
    point = bytes.fromhex(INPUTS["ephemeral"][PROFILES[profile]["point"]])

    if len(point) == 33 and COMPRESSED_IMPORT == "unsupported":
        return {
            "status": "unsupported",
            "reason": f"no compressed-point import through the runtime: {COMPRESSED_IMPORT_REFUSAL}",
        }

    key, nonce = sealing_material(profile, bind)
    carrier = gcm_seal(key, nonce, bytes.fromhex(INPUTS["dcaKeyHex"]), bind)
    envelope = point + carrier if PROFILES[profile]["derived"] else point + nonce + carrier

    flipped = bytearray(envelope)
    flipped[-TAG_BYTES - 1] ^= 0x01

    bad_point = bytes.fromhex(
        INPUTS["offCurvePoints"]["compressedHex" if len(point) == 33 else "uncompressedHex"]
    )
    off_curve = bad_point + envelope[len(point):]

    # A compressed x below p whose curve equation has no square root mod p. Only
    # a 33-byte point carries that case, so the probe records "n/a" for the wider profiles.
    non_residue = "n/a"
    if len(point) == 33:
        non_residue_envelope = (
            bytes.fromhex(INPUTS["offCurvePoints"]["compressedNonResidueHex"]) + envelope[len(point):]
        )
        non_residue = releases(profile, non_residue_envelope, bind)

    opened = open_envelope(profile, envelope, bind)

    return {
        "status": "answered",
        "envelopeHex": envelope.hex(),
        "derivedKeyHex": key.hex(),
        "derivedNonceHex": nonce.hex(),
        "envelopeBase64url": b64url(envelope),
        "decodedBytes": len(envelope),
        "base64urlChars": len(b64url(envelope)),
        "pointBytes": len(point),
        "openedKeyHex": opened.hex() if opened is not None else "open-failed",
        "wrongBind": releases(profile, envelope, INPUTS["otherBind"]["value"]),
        "flippedCiphertext": releases(profile, bytes(flipped), bind),
        "invalidPoint": releases(profile, off_curve, bind),
        "nonResiduePoint": non_residue,
    }


def derived_pair(pkcs8_hex, bind):
    shared = agree(bytes.fromhex(INPUTS["issuer"]["publicUncompressedHex"]), pkcs8_hex)
    return {
        "keyHex": hkdf(shared, HKDF_INPUTS["keyInfoPrefix"] + bind, HKDF_INPUTS["keyBytes"]).hex(),
        "nonceHex": hkdf(shared, HKDF_INPUTS["nonceInfoPrefix"] + bind, HKDF_INPUTS["nonceBytes"]).hex(),
    }


def main():
    detect_compressed_import()
    bind = INPUTS["bind"]["value"]
    observations = {
        "runtime": "python",
        "runtimeVersion": f"Python {sys.version.split()[0]}",
        "cryptoProvider": f"cryptography {cryptography.__version__}",
        "compressedPointImport": COMPRESSED_IMPORT,
        "profiles": {},
        "ephemeralReuse": {},
    }
    for profile in PROFILES:
        observations["profiles"][profile] = run_profile(profile)

    pairs = {
        "sameEphemeralSameBind": derived_pair(INPUTS["ephemeral"]["privatePkcs8Hex"], bind),
        "sameEphemeralSameBindRepeat": derived_pair(INPUTS["ephemeral"]["privatePkcs8Hex"], bind),
        "sameEphemeralOtherBind": derived_pair(INPUTS["ephemeral"]["privatePkcs8Hex"], INPUTS["otherBind"]["value"]),
        "freshEphemeralSameBind": derived_pair(INPUTS["ephemeralFresh"]["privatePkcs8Hex"], bind),
    }
    for profile, shape in PROFILES.items():
        if shape["derived"]:
            observations["ephemeralReuse"][profile] = pairs

    print(json.dumps(observations, indent=2))


main()
