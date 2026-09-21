"""Reading the recorded JWKs.

Exists because `cryptography` offers no JWK loader. An RSA private key is
rebuilt from five integers through `RSAPrivateNumbers`, an EC one from three
through `EllipticCurvePrivateNumbers`, each member a base64url big-endian
integer. Any Python implementation reading these keys writes this file first.
"""

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .codec import b64u_decode, b64u_int, pad32

#: P-256, the one curve the contract names.
CURVE = ec.SECP256R1()


class JwkError(Exception):
    """A recorded key that will not rebuild."""


def _member(jwk, name):
    value = b64u_int(jwk.get(name) if isinstance(jwk, dict) else None)
    if value < 0:
        raise JwkError(f"JWK member {name!r} is missing or is not canonical base64url")
    return value


def rsa_private_from_jwk(jwk):
    """An RSA private key from n, e, d, p, q.

    The three CRT members a JWK may also carry, dp, dq and qi, are recomputed
    rather than read. `cryptography` requires all three where Go's `Precompute`
    derives them, and recomputing keeps the key this file builds a function of
    the five values that define it: a vector whose recorded dp disagreed with
    its p and d would otherwise build a key that signs one way and opens
    another.
    """
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        raise JwkError(f"kty {jwk.get('kty') if isinstance(jwk, dict) else None!r}, not RSA")
    e = _member(jwk, "e")
    if e < 3 or e > 2 ** 31 - 1:
        raise JwkError("public exponent out of range")
    n = _member(jwk, "n")
    d = _member(jwk, "d")
    p = _member(jwk, "p")
    q = _member(jwk, "q")
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    )
    try:
        # Validation is on by default here, and it is what catches p*q != n.
        return numbers.private_key()
    except ValueError as err:
        raise JwkError(str(err)) from err


def point_from_jwk(jwk):
    """The 65-byte uncompressed SEC 1 point, 0x04 || X || Y.

    Each coordinate keeps its full 32-byte width, so a recorded key whose x or y
    begins with a zero byte encodes to the same 65 bytes as any other.
    """
    if not isinstance(jwk, dict):
        raise JwkError("no JWK to read a public point from")
    x = b64u_decode(jwk.get("x"))
    y = b64u_decode(jwk.get("y"))
    if x is None or y is None:
        raise JwkError("JWK x or y is missing or is not canonical base64url")
    x, y = pad32(x), pad32(y)
    if x is None or y is None:
        raise JwkError("JWK x or y is wider than the 32 bytes a P-256 coordinate carries")
    return b"\x04" + x + y


def ec_public_from_point(point):
    """A P-256 public key from its uncompressed encoding.

    `from_encoded_point` validates. It refuses a point that is off the curve
    here, at import, the way .NET refuses it; the JVM waits until the key
    agreement.
    """
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, point)
    except ValueError as err:
        raise JwkError(str(err)) from err


def ec_private_from_jwk(jwk):
    """A P-256 private key from d, with its recorded public point when there is one.

    Python will not build a private scalar on its own: `EllipticCurvePrivateNumbers`
    requires a public point and refuses one that is not the scalar's own, so a
    recorded key carries x and y beside d. When one carries only d,
    `derive_private_key` recomputes the point; the case still runs, and it loses
    the pairing check a recorded point would have given.
    """
    if not isinstance(jwk, dict):
        raise JwkError("no JWK to read a private key from")
    if jwk.get("kty") != "EC":
        raise JwkError(f"kty {jwk.get('kty')!r}, not EC")
    if jwk.get("crv") not in (None, "P-256"):
        raise JwkError(f"crv {jwk.get('crv')!r}, and the contract names P-256")
    scalar = b64u_decode(jwk.get("d"))
    if scalar is None or pad32(scalar) is None:
        raise JwkError("JWK d is missing, not canonical base64url, or wider than 32 bytes")
    d = int.from_bytes(scalar, "big")
    try:
        if jwk.get("x") is None or jwk.get("y") is None:
            return ec.derive_private_key(d, CURVE)
        return ec.EllipticCurvePrivateNumbers(
            d,
            ec.EllipticCurvePublicNumbers(_member(jwk, "x"), _member(jwk, "y"), CURVE),
        ).private_key()
    except ValueError as err:
        raise JwkError(str(err)) from err
