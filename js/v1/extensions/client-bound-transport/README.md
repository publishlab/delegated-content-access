# Client-bound transport extension

Status: implemented optional extension

This extension wraps issuer-delivered keys for one client's non-extractable
keypair. A deployment selects it. Base source has only injection seams and
imports nothing from this directory.

## Source placement

| Responsibility | Location |
| --- | --- |
| Client capability and private-key closure | `core-client/` |
| Method mechanics shared by client and issuer | `core-shared--client-issuer/` |
| Issuer sealing and wrapping | `core-issuer/` |
| Complete ECDH-P256 and RSA-OAEP profile surfaces | `ecdhP256.js`, `rsaOaep.js` |
| Tests owned only by this extension | `test/` |

ECDH-P256 and RSA-OAEP are methods inside this extension. They are not separate
extensions. The extension entry modules combine each method's role-specific
parts without changing the source ownership beneath them.

The host injects a client profile through
`clientBoundKeyCapability(keyPair, profile)` and injects the matching issuer
profile through `IssuerServer({ clientBoundProfile })`. Neither side chooses a
default method. Each method exports `RANDOM_REQUIRED` so the issuer host can
reject an incomplete deployment at construction. ECDH-P256 needs injected
nonce randomness; RSA-OAEP does not.

Run this extension's gate with:

    npm run test:reference:extension:client-bound-transport

Tests that compose this extension with another optional extension belong in
`test-extensions/`, not here. The recorded wire fixtures remain under
`verification/vectors/v1-profile--client-bound-*`; `test-vectors/client-bound-vectors.test.js`
owns their replay.
