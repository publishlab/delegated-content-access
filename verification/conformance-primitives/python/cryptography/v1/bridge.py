#!/usr/bin/env python3
"""What Python observes when it is asked to perform one of the contract's seven
operations, and nothing about whether that observation is right.

Five operations are one `cryptography` call each: derive octets with
HKDF-SHA-256, open and seal an AES-GCM carrier, agree a P-256 ECDH secret, and
open an RSA-OAEP ciphertext. Two are code written in this lane:
`primitives/codec.py` decides the strict base64url verdict over
`base64.urlsafe_b64decode`, and `primitives/jwk.py` lays out the P-256 point from
the JWK's `x` and `y` with no `cryptography` call. The README's "Who answers
what" names each member. This bridge joins nothing, slices nothing and derives
nothing between two calls. Every intermediate value arrives as a recorded input.

The bridge reads a single `dca-operation-bridge-v1`
JSON document from stdin, computes one observation per request, writes a single
JSON document to stdout and exits 0. Human diagnostics go to stderr; nothing
reads a result out of stderr, so a bridge may say whatever it likes there.

This file deliberately does not know what any observation
is supposed to be. There is no expected value here, no comparison, no `held`,
`disagreed` or `incomplete` word, no pass count and no total. It never opens the
case corpus, and the request it is handed carries no `expected` and no `class`
for it to peek at. The identifier it copies back is opaque and says nothing about
the answer, so nothing here reads it except to name a diagnostic line.

`primitives/` beside this file holds the library calls. `primitives/crypto.py`
is `cryptography`'s own AES-GCM, ECDH, HKDF and RSA-OAEP, `primitives/jwk.py`
rebuilds a recorded JWK because `cryptography` ships no reader for one, and
`primitives/codec.py` reads base64url strictly because no standard-library
setting does. That package carries no recorded value, no expectation and no
case, so importing it hands this bridge no answer it could not otherwise reach.

`invalid_base64url`, `authentication_failed` and
`unseal_failed` are observations inside an exit-0 result, because refusing
correctly is one of the behaviours under test. For a request the bridge cannot serve
at all (an unparseable batch, an unknown operation or an input shape outside the
contract), the bridge exits nonzero with a stderr line and
writes no partial results, and the driver reads that as a run that could not be
completed. No traceback ever reaches the operator in place of that line.

Every shape is closed, and this bridge checks each one. The envelope carries `protocol`
and `requests`, a request row carries `id`, `op` and `input`, and an input carries
exactly the members its operation names. `json.loads` reads any object at all, so
the check is written out here: a member nobody named means a harness is speaking a
protocol this bridge has not agreed to, and answering it anyway would let a
request quietly carry something the contract says cannot be there.

The runtime's own JSON parser reads the batch, and nothing else does. There is no
token scanner here. `json.loads` keeps the last spelling of a repeated member and
says nothing, and this bridge does not go looking: the driver writes the bytes on
stdin and never repeats a member, so a bridge defending against one would be
defending against its own harness, once per language.

Dependencies: the standard library, and `cryptography` for AES-128/256-GCM,
ECDH-P256, HKDF-SHA256 and RSA-OAEP. CPython has none of those of its own, and
nothing here vendors one. Verified on CPython 3.14.7 with cryptography 50.0.1,
which is what `python/install-toolchain` and `python/cryptography/install-libraries`
cache.

Run (the driver does this through `python/cryptography/v1/bridge`; by hand it is the same):
  printf '%s\n' '<batch json>' | python3 conformance-primitives/python/cryptography/v1/bridge.py
"""

import json
import os
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
except ImportError as error:  # pragma: no cover - reported, never worked around
    sys.stderr.write(
        "bridge: this bridge needs the cryptography package for AES-GCM, "
        f"and the interpreter running it has none: {error}\n"
    )
    raise SystemExit(1)

# `v1/` is this file's own directory, and CPython already puts a run script's
# own directory ahead of everything else in sys.path; the insert below spells
# that out rather than relying on it implicitly. The wrapper's PYTHONPATH
# carries only the wheelhouse `cryptography` lives in, never this directory by
# name, so `primitives/` reaches this process solely because it sits beside the
# script the wrapper starts.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from primitives.codec import b64u_decode_strict, b64u_encode  # noqa: E402
from primitives.crypto import (  # noqa: E402
    AES_KEY_WIDTHS,
    GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    ecdh,
    gcm_open,
    gcm_seal,
    hkdf_sha256,
    rsa_oaep_open,
)
from primitives.jwk import (  # noqa: E402
    JwkError,
    ec_private_from_jwk,
    ec_public_from_point,
    point_from_jwk,
    rsa_private_from_jwk,
)

BATCH_PROTOCOL = "dca-operation-bridge-v1"

# The output widths `hkdf-sha256` answers. RFC 5869 caps HKDF-Expand at 255
# SHA-256 blocks, 8160 octets, and a request for zero octets names no
# derivation.
HKDF_MIN_OCTETS = 1
HKDF_MAX_OCTETS = 8160


class BridgeFault(Exception):
    """A batch or a request this bridge cannot serve, which is never a refusal."""


def main() -> int:
    raw = sys.stdin.buffer.read()

    try:
        results = answer_batch(raw)
    except BridgeFault as fault:
        sys.stderr.write(f"bridge: {fault}\n")
        return 1
    except Exception as error:  # noqa: BLE001 - a traceback is not a diagnostic
        sys.stderr.write(f"bridge: {type(error).__name__}: {error}\n")
        return 1

    envelope = {"protocol": BATCH_PROTOCOL, "results": results}
    sys.stdout.write(json.dumps(envelope) + "\n")
    return 0


def answer_batch(raw: bytes) -> list:
    """The request envelope, read strictly, and one result per request in request order.

    Order is irrelevant to the driver, which keys results by the (id, op) pair, so
    request order is kept only because it makes a hand-read batch easy to follow.
    """
    try:
        request = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise BridgeFault(f"the batch on stdin is not UTF-8: {error}") from error
    except json.JSONDecodeError as error:
        raise BridgeFault(f"the batch on stdin is not readable JSON: {error}") from error

    if not isinstance(request, dict):
        raise BridgeFault("the batch on stdin is not a JSON object.")
    closed_members(request, ["protocol", "requests"], "the batch")
    if request["protocol"] != BATCH_PROTOCOL:
        raise BridgeFault("the batch names a protocol this bridge does not speak.")
    if not isinstance(request["requests"], list):
        raise BridgeFault("the batch carries no requests array.")

    results = []
    for entry in request["requests"]:
        if not isinstance(entry, dict):
            raise BridgeFault("a request entry is not a JSON object.")
        closed_members(entry, ["id", "op", "input"], "a request entry")
        entry_id = entry["id"]
        if not isinstance(entry_id, str) or entry_id == "":
            raise BridgeFault("a request entry carries no id.")
        if not isinstance(entry["op"], str):
            raise BridgeFault(f"request {entry_id} carries no op.")
        if not isinstance(entry["input"], dict):
            raise BridgeFault(f"request {entry_id} carries no input object.")

        results.append({
            "id": entry_id,
            "op": entry["op"],
            "observation": observe(entry["op"], entry["input"], entry_id),
        })

    return results


def observe(op: str, request_input: dict, entry_id: str) -> dict:
    """One observation for one request, or a fault when the operation is not one of the seven."""
    if op == "decode-base64url":
        return observe_decode_base64url(request_input, entry_id)
    if op == "hkdf-sha256":
        return observe_hkdf_sha256(request_input, entry_id)
    if op == "open-aes-gcm":
        return observe_open_aes_gcm(request_input, entry_id)
    if op == "seal-aes-gcm":
        return observe_seal_aes_gcm(request_input, entry_id)
    if op == "ecdh-p256":
        return observe_ecdh_p256(request_input, entry_id)
    if op == "p256-point":
        return observe_p256_point(request_input, entry_id)
    if op == "open-rsa-oaep":
        return observe_open_rsa_oaep(request_input, entry_id)
    raise BridgeFault(
        f"request {entry_id} names operation {op}, which this bridge does not implement."
    )


def observe_decode_base64url(request_input: dict, entry_id: str) -> dict:
    """The strict field spelling: RFC 4648 section 5 alphabet, no padding, a length
    that encodes a whole byte count, and zero unused trailing bits.

    Python's own decoder enforces none of those four on its own, so
    `primitives/codec.py` applies each one around it.

    Which rule fired goes to stderr. The observation carries the one closed code,
    because the contract defines one.
    """
    closed_members(request_input, ["value"], f"the input of request {entry_id}")
    value = required_string(request_input, "value", entry_id)
    decoded, why = b64u_decode_strict(value)
    if decoded is None:
        sys.stderr.write(f"bridge: {entry_id} refused {json.dumps(value)}: {why}\n")
        return {"refused": "invalid_base64url"}
    return {"bytesHex": decoded.hex()}


def observe_hkdf_sha256(request_input: dict, entry_id: str) -> dict:
    """One HKDF-SHA-256 derivation over the octets the request carries, with an
    empty salt, to the width the request asks for.

    This bridge keeps `info` as octets: the recorded values carry 0x00 and octets
    above 0x7f, and a text string type would alter them. A member this bridge
    cannot decode, or a width outside 1 through 8160, stops the batch, because
    this operation defines no refusal.
    """
    closed_members(
        request_input, ["ikmBase64url", "infoBase64url", "length"], f"the input of request {entry_id}",
    )
    ikm = carrier_bytes(request_input, "ikmBase64url", entry_id)
    info = carrier_bytes(request_input, "infoBase64url", entry_id)
    length = required_integer(request_input, "length", entry_id)
    if length < HKDF_MIN_OCTETS or length > HKDF_MAX_OCTETS:
        raise BridgeFault(
            f"request {entry_id} asks for {length} HKDF octets, and this operation derives "
            f"{HKDF_MIN_OCTETS} through {HKDF_MAX_OCTETS}."
        )

    return {"okmBase64url": b64u_encode(hkdf_sha256(ikm, b"", info, length))}


def observe_open_aes_gcm(request_input: dict, entry_id: str) -> dict:
    """AES-GCM over one `ciphertext || tag` carrier, the cipher chosen by the key's
    own width: 16 octets read AES-128-GCM and 32 read AES-256-GCM.

    A key or a nonce of another width is an input shape outside the contract and
    exits nonzero, because AESGCM would otherwise be handed a size it never
    agreed to. A carrier too short to hold a tag cannot verify, and the
    contract answers that with its authentication refusal under any cause.
    """
    closed_members(
        request_input,
        ["keyBase64url", "nonceBase64url", "ciphertextBase64url", "aadBase64url"],
        f"the input of request {entry_id}",
    )
    key = aes_key_bytes(request_input, entry_id)
    nonce = nonce_bytes(request_input, entry_id)
    carrier = carrier_bytes(request_input, "ciphertextBase64url", entry_id)
    aad = carrier_bytes(request_input, "aadBase64url", entry_id)

    if len(carrier) < GCM_TAG_BYTES:
        sys.stderr.write(
            f"bridge: {entry_id} carries {len(carrier)} byte(s), fewer than a {GCM_TAG_BYTES} byte tag.\n"
        )
        return {"refused": "authentication_failed"}

    plaintext = gcm_open(key, nonce, carrier, aad)
    if plaintext is None:
        sys.stderr.write(f"bridge: {entry_id} did not authenticate.\n")
        return {"refused": "authentication_failed"}

    return {"plaintextBase64url": b64u_encode(plaintext)}


def observe_seal_aes_gcm(request_input: dict, entry_id: str) -> dict:
    """The same two widths sealed: ciphertext with its 16-octet tag appended, under
    the nonce the request carries.

    Because the nonce is an input, a seal has one determined answer. The
    operation defines no refusal, so a key or a nonce of another width stops the
    batch.
    """
    closed_members(
        request_input,
        ["keyBase64url", "nonceBase64url", "plaintextBase64url", "aadBase64url"],
        f"the input of request {entry_id}",
    )
    key = aes_key_bytes(request_input, entry_id)
    nonce = nonce_bytes(request_input, entry_id)
    plaintext = carrier_bytes(request_input, "plaintextBase64url", entry_id)
    aad = carrier_bytes(request_input, "aadBase64url", entry_id)

    carrier = gcm_seal(key, nonce, plaintext, aad)
    if carrier is None:
        raise BridgeFault(f"request {entry_id} could not be sealed under this key or nonce width.")

    return {"ciphertextBase64url": b64u_encode(carrier)}


def observe_ecdh_p256(request_input: dict, entry_id: str) -> dict:
    """One ECDH agreement over P-256, between the recorded private key and the
    peer's 65-octet uncompressed point.

    The answer is the agreed x-coordinate at the full field width, 32 octets,
    leading zero octets kept. The operation defines no refusal, and a point
    `cryptography` cannot import stops the batch.
    """
    closed_members(
        request_input, ["privateKeyJwk", "peerPointBase64url"], f"the input of request {entry_id}",
    )
    private_key = jwk_or_fault(
        ec_private_from_jwk,
        required_object(request_input, "privateKeyJwk", entry_id),
        "privateKeyJwk", entry_id,
    )
    point = carrier_bytes(request_input, "peerPointBase64url", entry_id)
    try:
        peer_public = ec_public_from_point(point)
    except JwkError as error:
        raise BridgeFault(
            f"request {entry_id} carries a peerPointBase64url this bridge cannot import: {error}."
        ) from error

    return {"sharedSecretBase64url": b64u_encode(ecdh(private_key, peer_public))}


def observe_p256_point(request_input: dict, entry_id: str) -> dict:
    """One recorded public key written as the 65-octet uncompressed SEC 1 point:
    the octet 0x04, then x, then y, each coordinate at its full 32-octet width.

    The operation defines no refusal, and a key this bridge cannot read stops the
    batch.
    """
    closed_members(request_input, ["publicKeyJwk"], f"the input of request {entry_id}")
    point = jwk_or_fault(
        point_from_jwk,
        required_object(request_input, "publicKeyJwk", entry_id),
        "publicKeyJwk", entry_id,
    )
    return {"pointBase64url": b64u_encode(point)}


def observe_open_rsa_oaep(request_input: dict, entry_id: str) -> dict:
    """One RSA-OAEP-SHA256 decryption to the whole plaintext, through
    `primitives/crypto.py`'s `rsa_oaep_open`.

    A wrong private key, a ciphertext that is not one modulus wide and a flipped
    byte are one padding failure; OAEP's own check does not tell them apart.
    """
    closed_members(
        request_input, ["ciphertextBase64url", "privateKeyJwk"], f"the input of request {entry_id}",
    )
    private_key = jwk_or_fault(
        rsa_private_from_jwk,
        required_object(request_input, "privateKeyJwk", entry_id),
        "privateKeyJwk", entry_id,
    )
    ciphertext = carrier_bytes(request_input, "ciphertextBase64url", entry_id)

    plaintext = rsa_oaep_open(private_key, ciphertext)
    if plaintext is None:
        return {"refused": "unseal_failed"}

    return {"plaintextBase64url": b64u_encode(plaintext)}


def aes_key_bytes(request_input: dict, entry_id: str) -> bytes:
    """The AES key, 16 or 32 octets, or a request this bridge cannot serve. The
    key's width selects the cipher, and no other width has one.
    """
    key = carrier_bytes(request_input, "keyBase64url", entry_id)
    if len(key) not in AES_KEY_WIDTHS:
        raise BridgeFault(
            f"request {entry_id} carries a {len(key)} byte key, and AES-GCM here takes "
            f"{' or '.join(str(width) for width in AES_KEY_WIDTHS)}."
        )
    return key


def nonce_bytes(request_input: dict, entry_id: str) -> bytes:
    """The 12-byte GCM nonce both AES-GCM operations take, or a request this bridge
    cannot serve: the contract fixes the width and it is never a refusal.
    """
    nonce = carrier_bytes(request_input, "nonceBase64url", entry_id)
    if len(nonce) != GCM_NONCE_BYTES:
        raise BridgeFault(
            f"request {entry_id} carries a {len(nonce)} byte nonce, and this carrier takes {GCM_NONCE_BYTES}."
        )
    return nonce


def required_object(request_input: dict, member: str, entry_id: str) -> dict:
    """One input member that must be present and a JSON object, or a request this
    bridge cannot serve.
    """
    value = request_input.get(member)
    if not isinstance(value, dict):
        raise BridgeFault(f"request {entry_id} carries no {member} object.")
    return value


def jwk_or_fault(loader, jwk: dict, member: str, entry_id: str):
    """One JWK read through `primitives/jwk.py`, or a request this bridge cannot
    serve: `JwkError` is exactly "a JWK the runtime cannot import", which this
    contract answers with a nonzero exit rather than a refusal.
    """
    try:
        return loader(jwk)
    except JwkError as error:
        raise BridgeFault(f"request {entry_id} carries a {member} this bridge cannot import: {error}.") from error


def closed_members(obj: dict, members: list, what: str) -> None:
    """One JSON object holding exactly the named members, or a request this bridge
    cannot serve.

    The contract calls the envelope, the request row and every input closed, and a
    closed shape nobody checks exists only in a document. A member outside the set
    means the sender is writing a protocol this bridge has not agreed to, and a missing
    one means it left out something the operation is defined by.
    """
    present = list(obj)
    unknown = [name for name in present if name not in members]
    absent = [name for name in members if name not in obj]

    if unknown or absent:
        raise BridgeFault(
            f"{what} carries {{{', '.join(present)}}}, and it carries {{{', '.join(members)}}} exactly."
        )


def required_string(request_input: dict, member: str, entry_id: str) -> str:
    """One input member that must be present and a string, or a request this bridge cannot serve."""
    value = request_input.get(member)
    if not isinstance(value, str):
        raise BridgeFault(f"request {entry_id} carries no string {member}.")
    return value


def required_integer(request_input: dict, member: str, entry_id: str) -> int:
    """One input member that must be present and a JSON integer. Python counts
    `True` as an `int` and reads `2.0` as a `float`, so this refuses both by
    hand.
    """
    value = request_input.get(member)
    if not isinstance(value, int) or isinstance(value, bool):
        raise BridgeFault(f"request {entry_id} carries no integer {member}.")
    return value


def carrier_bytes(request_input: dict, member: str, entry_id: str) -> bytes:
    """One base64url input member decoded to raw bytes. Every recorded value is
    canonical, so a spelling that does not decode means the batch was written
    wrong, and that stops the batch.
    """
    value = required_string(request_input, member, entry_id)
    decoded, why = b64u_decode_strict(value)
    if decoded is None:
        raise BridgeFault(
            f"request {entry_id} carries a {member} this bridge cannot decode: {why}."
        )
    return decoded


if __name__ == "__main__":
    sys.exit(main())
