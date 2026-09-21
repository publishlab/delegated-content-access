"""base64url as the contract spells it.

This file exists only for the decoder. Python's base64url
decoder admits more spellings of one value than any other runtime the contract
has been probed on, and no setting in the standard library narrows it to the one
canonical spelling:

    base64.urlsafe_b64decode(s)                  translates '-_' -> '+/' and then
                                                 decodes on the STANDARD alphabet
    -> '+' and '/' decode, to the same bytes as '-' and '_'
    -> validate defaults to False, so every character outside the alphabet is
       DISCARDED before the length check, junk and whitespace alike
    -> unpadded input, which is every value in the corpus, RAISES; a caller has
       to supply the padding first
    -> once padded, '=' is consumed rather than counted: excess '=' past a whole
       quad is ignored and decoding CONTINUES past it, so "<v>==<v>==" yields a
       bit-shifted 33 bytes rather than an error
    -> non-zero unused trailing bits are accepted

    base64.b64decode(s, altchars=b'-_', validate=True)   the strictest call there
                                                         is, and still not enough
    -> fixes junk, whitespace, excess padding and data-after-padding
    -> STILL accepts '+' and '/', because altchars translates before it validates
    -> STILL accepts non-zero unused trailing bits

So the canonical decoder below runs an explicit alphabet test, then a decode,
then a re-encode compared against the input. Every runtime needs the re-encode;
only Python needs the alphabet test.
"""

import base64
import binascii

#: The 64 characters the contract writes a value in, and the only ones the
#: decoder takes.
B64U_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def b64u_encode(raw):
    """Unpadded base64url, the one spelling anything here writes."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode_strict(value):
    """`(bytes, None)` for a canonical spelling, `(None, reason)` for every other.

    The four rules the contract names, in the order they are cheapest to apply:
    the alphabet, a length that encodes a whole byte count, no padding, and no
    unused trailing bits. Rule 3 falls out of rule 1, since '=' sits outside the
    alphabet.

    The reason is a sentence for a person reading stderr. It never reaches an
    observation, because the contract carries one refusal code here whichever
    rule fired.
    """
    if not isinstance(value, str):
        return None, "a value that is not a string"
    if value == "":
        return b"", None
    if not all(c in B64U_ALPHABET for c in value):
        return None, "a character outside the base64url alphabet, which includes padding"
    if len(value) % 4 == 1:
        return None, "a length that encodes no whole byte count"
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None, "bytes the base64 decoder would not read"
    # Non-zero unused trailing bits survive every check above and are the last
    # non-canonical spelling left. Re-encoding separates them.
    if b64u_encode(raw) != value:
        return None, "unused trailing bits: the value does not re-encode to itself"
    return raw, None


def b64u_decode(value):
    """The octets of a canonical spelling, or None for every other spelling.

    None rather than an exception, so when a JWK member will not decode, the
    caller refuses the key by name rather than failing with a traceback.
    """
    raw, _ = b64u_decode_strict(value)
    return raw


def b64u_int(value):
    """A JWK's big-endian integer member. -1 marks a member that will not decode."""
    raw = b64u_decode(value)
    return -1 if raw is None else int.from_bytes(raw, "big")


def pad32(raw):
    """A 32-byte field element: left zero padded, and never narrowed.

    A P-256 coordinate and a shared secret are fixed-width, and about one in 256
    of them begins with a zero byte. Trimming one shortens the value and feeds a
    different-length input to whatever reads it next.

    An input wider than 32 bytes is a different number rather than a P-256 value
    with a leading byte to drop, so this returns None and the caller refuses the
    key rather than reshaping it into one the other runtimes cannot read.
    """
    if len(raw) > 32:
        return None
    return b"\x00" * (32 - len(raw)) + raw
