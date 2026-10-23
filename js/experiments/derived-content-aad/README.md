# Content AAD source and representation comparison

Current baseline: fresh independent 16-byte content key used for one encryption,
twelve zero nonce bytes, and `LP(renderId) || LP(contentName)` as AES-GCM AAD.
LP is a four-byte big-endian UTF-8 byte length followed by the UTF-8 bytes.
Items carry neither nonce nor AAD. Type, encodings and other token claims are
outside the current content tag; admitted changes can alter processing without
failing authentication. Capture and handling admission remain required.
Issuers still verify claims and authorize requests; cached opening need not
contact them. Render/name relabeling is bound by content AAD and, for period-key recovery,
by the derived wrap nonce.
[Content protection Section 3](../../../docs/spec--content-protection.md#3-base-protected-item-transcript)
defines the current procedure. Current tests compare that procedure with the
historical controls; the historical run counts below do not establish current
adoption evidence.

## Historical construction and experiment narrative

The remainder records the 2026-10-15 signing-input adoption and earlier controls.
References below to "adopted", "stock", "now" and "current" describe that
historical construction, which the two-field AAD has superseded. Its claims
about authenticated type, encoding and signing-input spelling do not apply to
the current baseline. Retain this narrative to explain the controls; consult
the current test sources for their present comparisons.

Status: experiment. The signing-input candidate compared here was adopted on
2026-10-15 as the `dca-bind-content` content AAD
([content protection](../../../docs/spec--content-protection.md) Section
3.2); its candidate domain `dca-bind-content-signing-input-v1` was renamed and
nothing else changed. The old carried format and the other candidates remain
here as historical controls.

Before adoption, v1 required the publisher to carry
`aad = resourceId|1|contentName` in each item record, and the client opened
AES-GCM under those carried bytes. The publisher could not choose an arbitrary
opaque AAD: the content-protection spec fixed its grammar. Now the publisher
seals under the derived transcript and omits `aad`; the stock client builds the
transcript from the `resourceJWT` signing input and the item's handling fields
and ignores a carried `aad`. The optional top-level `resource` object is
diagnostic; unlock relays and the issuer verifies `resourceJWT`, not
`resource.resourceId`.

The old-format cases are explicit controls. No current publisher writes an
old-format page, so `test-lib/oldFormat.js` takes an authentic current render
and the item keys a real issuer granted for it, and reseals each item under the
old carried string. `test-lib/harnesses/CarriedAadClient.js` opens under the
carried string, as every client did before adoption.

`comparison.test.js` retains an older proposal that rebuilds the old carried
grammar from that diagnostic mirror. A stock issuer accepts an old-format render
after the carried AAD is changed because it does not process content AAD; that
render is structurally admitted but violates the old producer transcript. The
historical client can decrypt it because it ignores the field. The test also
shows a mirror-absent delivery that the adopted client and the old carried
client open but the historical client cannot, and a mirror mismatch that
changes the historical client's AAD without changing the issuer's verified
claims. A fresh render shows that old and new formats do not open each other's
seals, and that a carried `aad` of any value or type leaves the stock client's
opening unchanged.

Two local comparisons deliberately bypass full DCA validity. An arbitrary-AAD
page uses a fake JWT, placeholder issuer envelope and manually injected key;
its opening on the old carried client shows parser/AEAD behavior, not a
conforming publisher freedom, and the stock client refuses it. A cross-slot
swap uses the same item key in two slots, contrary to the required independent
key per item and render, and again injects keys. It shows
that a carried AAD travels with its record while a slot-derived AAD stays at
the slot **in that invalid key-sharing setup**. Under required independent
item keys, the test's direct cross-slot ciphertext swap fails even with no AAD.
Neither local comparison demonstrates a conforming exchange or provenance
from successful decryption.

The stock publisher/issuer/client comparison moves whole records, not just
ciphertext. With independent item keys and a real authorized period grant,
the current derived wrap nonce rejects a record moved to another item name or
render during key recovery (`no_key`), before content AAD is checked. These
controls therefore exercise the complete current protection, rather than
claiming to isolate content AAD from the wrap transcript.

The historical comparison explicitly reseals both content and its period-key
wraps with carried random nonces. A small historical AEAD opener uses the real
issuer-granted period bytes directly; the current client never learns a legacy
wrap-opening path. In that control, moving a whole record also moves its
carried wrap nonce and content AAD, and its authorized plaintext opens in the
other slot or render. Both same-group source items were already covered by the
grant: the difference is selected slot/render integrity, not entitlement
expansion. The item-key-only control still shows that the first item's direct
key cannot open the second item's record.

`token-representation-candidate.test.js` compares historical signing-input
and full-token transcripts with the old carried string. Its local comparator
pins recorded candidate octets; it does not run the current production AAD.
The [content-protection specification](../../../docs/spec--content-protection.md#32-content-aad)
defines the current render/name construction.

The historical controls test type, ordered encoding and slot mutations. A real
ES256 key signs the same protected header and claims twice; both different
signature tokens pass the DCA JWT signature verifier. The signing-input
candidate opens the same ciphertext for either token, while full-token AAD
refuses the second. Changing signed claims or the protected kid changes the
signing-input candidate. A damaged signature segment leaves that candidate
unchanged: a client holding a key can still open the content, although the
issuer rejects the damaged token at a new unlock. These are raw-AEAD component
comparisons, not current content-decoder or provenance evidence.

| Choice                                                              | Integrity and reach                                                                                                                                                                                                                                                                                                                                                                                     | Function and cost                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Old carried AAD (before 2026-10-15)                                 | Authenticates ciphertext under the selected key and carried AAD. Independent item keys block direct ciphertext swaps, but a reusable period grant opens a complete moved item record and its own key in another selected slot or render. Type and encoding metadata remain outside the transcript. No source or placement provenance follows.                                                           | The pre-adoption v1 behavior, now an old-format control. Repeated AAD wire bytes; issuer and client need no extra claim parsing.                                                                                                                                                             |
| Historical mirror rebuild                                           | Slot name enters locally rebuilt bytes, but `resource.resourceId` is optional and unauthenticated. Does not repair issuer authorization or source provenance.                                                                                                                                                                                                                                           | Breaks valid mirror-absent deliveries and depends on a diagnostic copy that can disagree with signed claims. It is not a viable baseline as written.                                                                                                                                         |
| Earlier full-token transcript                                       | Binds selected handling fields and every compact-token byte. Local AEAD checks reject the tested moved-record substitutions with the same recovered key. It also refuses signature-segment damage without verifying the signature; a key holder can still forge another tuple and complete copies remain copyable.                                                                                      | Removes carried AAD, but a different valid signature over byte-identical header and claims requires resealing. The earlier proposal also chose a fresh render/key/envelope snapshot for any token-byte change.                                                                               |
| Adopted `dca-bind-content` transcript (the signing-input candidate) | Binds selected handling fields and the exact protected-header and payload segments, including their spelling, without decoding or verifying claims. The stock client refuses the tested slot and changed-render substitutions under a real period grant. Signature-only changes leave the AAD unchanged, including a damaged signature that the issuer would reject; opening alone gives no provenance. | Removes carried AAD and permits valid signature-only refresh without resealing. The client checks compact shape and builds a local transcript. A changed signed segment still requires a new render/key/envelope snapshot under the authoring rule. Old and new readers do not interoperate. |

The adopted transcript has a concrete advantage when an attacker can change
representation metadata before a trusted client decodes or hands off plaintext.
How valuable that is depends on the selected decoder and host's treatment of
type and placement; this experiment does not measure that risk. The per-item
key rule limits direct ciphertext swaps, but only the adopted transcript stops
the complete-record substitutions shown under a reusable period grant. Whether
an authenticated source or placement property is wanted stays open. The
security model leaves source retrieval and host placement to their owners.

Run from `js/`:

```sh
node --test --test-reporter=spec experiments/derived-content-aad/test/*.test.js
```

The focused run on 2026-10-11 passed 23 tests with no skips or TODOs, before
adoption. After adoption the suite compares the production transcript with the
old-format controls; it is component and historical-behavior evidence, not the
adoption evidence, which lives with the core tests.
