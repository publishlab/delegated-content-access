# Selected browser-Origin issuer admission contract

This target explicitly selects `dca-profile-browser-origin`. It is not a baseline
issuer duty or a complete conformance test for that profile. It exercises raw
serialized JSON requests and a separately supplied observed Origin through the
implementation's real browser admission composition.

Run from `js/`:

```sh
npm run test:contract:issuer-browser-origin -- test-contract/issuer-browser-origin/bindings/reference-issuer-browser-origin-binding.js
```

## Driver and observations

The binding supplies key-import operations and `createBrowserIssuer(config)`.
The resulting `unlock(rawRequest, {origin, hostContext})` returns the HTTP
adapter's unaltered `{status, headers, body}` result. The config supplies trusted
operating issuer names, registration lookup, caller admission, access policy and
clock. The reference driver uses `createIssuerCore` and `createBrowserIssuer`,
which executes `admitBrowserRequest`; it does not implement its own Origin test.
A port must invoke its corresponding selected browser composition.

The harness records registration, caller, policy and registration-scoped opening
callbacks. These collaborator observations are separate from the response body:
they establish that matched Origin reaches policy before opening, while a
mismatch or unknown registration reaches neither. A separately signed publisher
with no opening key cannot fall back to another publisher's usable private key.
The positive control proves that the other view's key really opens the recorded
sealed item. A port binding must preserve the supplied callback boundaries;
wire-only access without these observations does not implement this target.

The target reuses the checked-in `seal-ecdh` fixture's signing/opening material,
sealed item and expected content-key bytes. It selects only `sealed.contentKeys`
from that fixture: the fixture package location does not claim period-key
coverage. A harness-generated second publisher signing key and signed assertion
supply the registration-isolation control. No recorded vectors are changed or
regenerated, and no primitive corpus is extended.

This proves selected Origin/registration/policy/opening ordering in the supplied
composition. The observed Origin is a harness input, not evidence of deployed
TLS, proxy correctness, browser enforcement, complete profile conformance or
external host response-cache isolation. No optional profile is inferred from an
ordinary issuer endpoint's behavior.

<!-- contract-target
{
  "directory": "issuer-browser-origin",
  "test": "issuer-browser-origin.contract.test.js",
  "runner": "test:contract:issuer-browser-origin",
  "requiredAccess": "selected browser issuer composition with host callback instrumentation",
  "versions": [
    "1"
  ],
  "deliveryModes": [
    "direct"
  ],
  "contractProfiles": [
    "dca-profile-browser-origin"
  ],
  "observations": [
    "registration-policy-opening-order"
  ],
  "fixtureSets": [
    "fixtures/v1/profiles/dca-profile-period-keys/issuer-admission"
  ],
  "fixtureConsumer": "base-contract",
  "fixtureFormats": [
    "1"
  ],
  "selection": "selected-profile"
}
-->
