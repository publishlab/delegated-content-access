# Selected HTML-writer contract

Run `npm run test:contract:html-writer -- path/to/binding.js` from `js/`.
The binding exports `dcaTestBinding.targets["html-writer"]` with the capabilities
below and `driver.writeMarkup(input)`, returning an HTML fragment or a promise
of one. `input` contains `dcaData` (the JSON data-carrier value) and
`sealedContent` (the JSON array of named ciphertext records). A binding may adapt
these values to its writer's public API; it must call the supplied writer.

The contract imports no reference writer. It parses the fragment in a full
WHATWG HTML document with scripting enabled using parse5. It checks exactly one
body carrier of each reserved class, decoded JSON equality including unknown
fields, and an intact following sentinel. It permits any safe JSON escaping,
HTML attribute ordering, and carrier ordering. This is a small selected writer
boundary, not complete HTML-carrier profile conformance or a browser execution
test. It does not test cryptography or the carrier reader.

The local aggregate explicitly runs the reference binding. Its validator also
runs the deliberate slash-only writer negative proof and the `noscript` parser
mode control. The slash-only writer is a faulty test binding, never an adapter
for a native implementation. No native-port result is claimed.

<!-- contract-target
{
  "directory": "html-writer",
  "test": "html-writer.contract.test.js",
  "runner": "test:contract:html-writer",
  "requiredAccess": "markup writer callback returning an HTML fragment",
  "versions": [
    "1"
  ],
  "deliveryModes": [
    "markup"
  ],
  "contractProfiles": [
    "dca-profile-html-carrier"
  ],
  "observations": [
    "body-carrier-values-and-following-sentinel"
  ],
  "fixtureSets": [
    "fixtures/v1/profiles/dca-profile-html-carrier/script-text"
  ],
  "fixtureConsumer": "base-contract",
  "fixtureFormats": [
    "html-writer/1"
  ],
  "selection": "selected-profile"
}
-->
