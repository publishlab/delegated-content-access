# BIND anchored on renderId and slot

The controls remove parts of the shipped binding and show what then opens.
`implementation/` holds `bind.js`, a delimiter-less join;
`unboundSealing.js`, a decoder with no binding checks; and `naiveSealing.js`
over that join. `test/comparison.test.js` compares them with shipped BIND and
key sealing on ECDH P-256 and RSA-OAEP. Its shared sealed-section harness calls
envelope primitives directly and models grants and a deliberately unsafe
wrapper-slot lookup. It does not run signature verification, policy, keyId
registration or a complete issuer exchange.

The delimiter-less join collides for `premium1`/`251023T13` and
`premium`/`1251023T13`. **Both period labels are invalid in current DCA.** A
separate control runs current period-key request admission: it rejects both
labels and admits the valid `251023T1300` coordinate. The historical collision
remains useful serialization evidence, but does not demonstrate an attack
through the current issuer path.

Unbound envelopes permit relabeling. On ECDH, omitting the AAD also prevents
opening a bound envelope. On RSA, an unbound decoder with the same private key
returns the bound plaintext, `BIND || key`: that **discloses the key** even if
a later AES consumer rejects the oversized result. The test moves a premium
envelope to a permitted slot, extracts its final 16 bytes and decrypts a test
ciphertext under the denied item's key. The bound decoder refuses the same
relabel before release.
Trying an unbound decoder after bound decoding fails also reopens relabeling.
These are deliberately unsafe experimental configurations, not defects in the
current bound decoder. Decoder names or keyId labels alone do not isolate
configurations that share an opening private key.

Envelope width is unchanged for the tested 16-byte payloads and issuer key
sizes (109 decoded bytes for ECDH and 256 for RSA-2048). This is a bounded
measurement, not a claim about arbitrary payloads or RSA modulus sizes.

`test/bind-self-test.test.js` replays the checked-in
`verification/vectors/v1/experiments/bind-on-renderId-and-slot/bind-blobs.json` through the
standard `bindSelfTest` harness and separates a concrete binding mistake from
request tampering. Both entry points run their complete selected assertions
to completion. Run from `js/` with:

```sh
node --test --test-reporter=spec experiments/bind-on-renderId-and-slot/test/*.test.js
```
