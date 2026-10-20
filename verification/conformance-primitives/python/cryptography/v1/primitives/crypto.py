"""The library calls that the contract's operations rest on, with the rules
`cryptography` leaves to a caller.

This file keeps two rules:

    an HKDF object is single use. `derive()` twice on one raises AlreadyFinalized,
    where the JVM helper and .NET's HKDF.DeriveKey are stateless calls. A loop
    transliterated from either lane breaks on its second case, so every
    derivation below builds its own object.

    AESGCM takes any nonce from 8 to 128 bytes. The contract fixes 12, and a lane
    that leaves that to the library seals under a nonce width no other runtime
    will produce.

The library keeps two more: `AESGCM.encrypt` returns one ciphertext||tag buffer,
which is what WebCrypto, Go, PHP and the JCA all produce, and `padding.OAEP`
defaults neither hash, so the JDK's silent SHA-1 MGF1 has no analogue to fall
into here.
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .codec import pad32

#: The two AES key widths the contract carries. 16 octets select AES-128-GCM and
#: 32 select AES-256-GCM; the key's own width picks the cipher, and no input
#: member names one.
AES_KEY_WIDTHS = (16, 32)

#: The one GCM nonce width, and the rule this file keeps for the library.
GCM_NONCE_BYTES = 12

#: The GCM tag, appended to the ciphertext in the same buffer.
GCM_TAG_BYTES = 16

#: RSA-OAEP over SHA-256, both the digest and the MGF1 mask. Two hash arguments
#: and neither has a default: to get them apart, a caller has to name two hashes on one
#: line. `label=None` and `label=b""` are the same empty label, and the contract
#: carries none.
OAEP_SHA256 = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def hkdf_sha256(ikm, salt, info, length):
    """One derivation, on an object built for it and thrown away after.

    `salt=None` and `salt=b""` are the same zero-length salt here, agreeing with
    .NET's built-in and with the 32 zero bytes the JVM lane widens an empty salt
    to by hand.
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def ecdh(private_key, peer_public_key):
    """The raw P-256 agreement, the full field width, zero padded.

    `exchange` answers the raw x coordinate with no KDF applied and the library
    offers no hashing variant, so .NET's DeriveKeyMaterial trap has no counterpart
    here. The pad is a redundant safeguard: this library already answers 32 bytes for a
    secret whose leading byte is zero.
    """
    return pad32(private_key.exchange(ec.ECDH(), peer_public_key))


def gcm_seal(key, nonce, plaintext, aad):
    """ciphertext||tag in one buffer, or None when an input is the wrong width."""
    if len(key) not in AES_KEY_WIDTHS or len(nonce) != GCM_NONCE_BYTES:
        return None
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def gcm_open(key, nonce, ct_and_tag, aad):
    """The plaintext, or None on a tag failure or a wrong-width input.

    None and never an exception, because a refusal case asks for a carrier that
    will not open.
    """
    if len(key) not in AES_KEY_WIDTHS or len(nonce) != GCM_NONCE_BYTES:
        return None
    try:
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        return None


def rsa_oaep_open(private_key, ciphertext):
    """A recorded RSA-OAEP-SHA256 ciphertext opened, or None when it will not open."""
    try:
        return private_key.decrypt(ciphertext, OAEP_SHA256)
    except ValueError:
        return None
