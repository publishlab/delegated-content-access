"""The library calls that the Python operation bridge (`../bridge.py`) relies on.

Three modules rather than one file, because two of them exist only where Python
has no answer of its own. `codec` reads base64url, since
`base64.urlsafe_b64decode` accepts more spellings than any other runtime here
reads. `jwk` rebuilds a recorded key, since `cryptography` ships no JWK reader.
`crypto` calls `cryptography`'s own AES-GCM, ECDH, HKDF and RSA-OAEP.

Nothing under this package imports anything outside `cryptography` and the
standard library. The bridge claims that the Python environment itself produces and
reads the octets it is asked about, and a claim leaning on a JOSE library is a
claim about that library.
"""
