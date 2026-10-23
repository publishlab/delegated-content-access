# Nonce-free ordinary ECDH envelope experiment

Status: retained experimental comparison and specialized tests. Ordinary core
ECDH now adopts this carrier and nonce construction; no profile or catalogue
entry is needed. Use ordinary `ecdh-p256` in new integrations. Response nonces
remain unchanged. This directory retains independent primitive evidence, not a
second recommended production procedure or a conformance claim.

## Construction and selection

This prototype retains ordinary P-256 raw shared x-coordinate AES-256-GCM
and **all existing BIND AAD**. Each seal internally generates a fresh independent
P-256 pair and performs one encryption under that agreement with twelve zero
nonce octets. The carrier is `uncompressed ephemeral point || ciphertext/tag`:
65 + 16 + 16 = **97 bytes**, or **130 base64url characters**, matching adopted
ordinary ECDH. The former ordinary layout was 109 bytes / 146 characters.
No separate nonce field is transmitted.

Reopening or retransmitting a saved envelope is allowed. Reusing an agreement
for another seal is not; callers cannot inject a pair into this producer.
The producer snapshots the key bytes and BIND before its first async step.
This is the minimal omission experiment, not HPKE or point compression.
Compact-ECDH HPKE and RSA are unaffected. Content-group seed envelopes now use
the same zero-nonce construction for their 32-byte payload, in their own code.

The retained experimental publisher/issuer composition uses the local procedure
`experimental-nonce-free-envelope`. It is an experimental selector used by the
existing injection seam, not a registered protocol/profile identifier.
Import `nonceFreeEnvelopePublisherContribution()` from
`core-publisher/keySealing.js`, compose it through `composePublisherConfig`,
and set the chosen issuer's `envelope` to that selector. Import
`nonceFreeEnvelopeIssuerContribution()` from `core-issuer/procedure.js` and
pass it to `createIssuerCore`; that issuer's opening-key entry must permit the
selector in its `envelopes` list and hold its ordinary ECDH private key.
`test/exchange.test.js` is the executable composition example.

The prototype and adopted ordinary carrier interoperate. Both reject the former
109-byte carried-nonce layout without fallback. Without an `envelope` selection
the publisher adapter delegates to ordinary core sealing; no experimental
selector is needed to omit the nonce.

## Seams and copied code

- Publisher `keySealing` contributions and issuer `envelopeProcedures` already
  suffice for a real publisher → client relay → issuer → client content-opening
  exchange. The issuer reconstructs existing BIND before calling the procedure.
- Core `core-shared--publisher-issuer/keySealing.js` offers no carrier-layout
  seam. `core-shared--publisher-issuer/envelope.js` therefore reproduces its
  small ECDH orchestration and width/point checks, originally changing the nonce/carrier.
  It reuses base crypto-provider, AEAD, codec and BIND operations. This independent
  implementation remains a test comparison after core adoption, rather than a
  dependency of core or an additional production requirement.
- Publisher selector routing and issuer contribution adapters follow the
  compact-ECDH adapter pattern; they import no compact-ECDH implementation.
- Integration test setup follows `../compact-ecdh/test/exchange.test.js`;
  there is no production dependency on that extension.

## Tests

From `js/`:

```sh
node --test 'extensions/nonce-free-envelope/test/*.test.js'
pnpm exec eslint extensions/nonce-free-envelope
pnpm exec prettier --check extensions/nonce-free-envelope
```

The shared [`../../test-lib/suites/envelope-behavior.js`](../../test-lib/suites/envelope-behavior.js)
suite takes a small recipient/seal/open adapter.
It contains carrier-independent key recovery, replay opening, wrong recipient
and BIND relabel assertions for render, content name, kind, access group,
period label, chain position and both geometry dimensions. The same assertions
run against ordinary core in
`../../test-reference/core-shared/keySealing.test.js` and against this extension
through its comparison adapter. Period and chain cases exercise supported
envelope BIND vocabulary; they select no derivation implementation and establish
no complete optional-profile conformance claim.

The primitive tests include the Buffer snapshot regression and bidirectional
prototype/core interoperability with strict refusal of the former carrier.

Special tests also stay here: 97-byte layout, zero-nonce known answer,
fresh-pair production behavior, former carrier rejection, input snapshots,
explicit procedure selection and contribution integration.

The literal known-answer transcript was computed with `node:crypto`
`createECDH` / `createCipheriv` using publicly disclosed test scalars 1 and 2,
zero nonce and the stated content BIND. It independently fixes the opening
answer. Another test opens generated production envelopes with Node's stock
`createDecipheriv`, independently of the base WebCrypto AEAD wrappers. This
is implementation evidence, not independent library-provider or language
conformance: Node's interfaces may share the same underlying crypto provider.
The original experiment introduced no profile or conformance claim. Core
adoption updates the ordinary specification and its current evidence separately.
Freshness sampling checks the implementation path, not a statistical proof
of the random generator or a general cryptographic proof.
