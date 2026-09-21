// Runs the reference endpoint-port checks against the recorded ECDH render in
// `verification/fixtures/protocol-v1/seal-ecdh.json`. The checks unlock that
// recorded request through the reference processor and endpoint and pin the
// status and body each adapter failure maps to. The request comes from the
// recorded file, so a change to the sealing code cannot change what these
// checks send.

import { readFileSync } from "node:fs";

import { referenceIssuerEndpointPortChecks } from "../test-lib/suites/reference-issuer-endpoint-port.js";
import { referenceIssuerEndpointPortDriver } from "../test-lib/adapters/reference-issuer-endpoint-port-driver.js";

const endpointContractVector = JSON.parse(
  readFileSync(
    new URL("../../../verification/fixtures/protocol-v1/seal-ecdh.json", import.meta.url),
    "utf8",
  ),
);

referenceIssuerEndpointPortChecks(referenceIssuerEndpointPortDriver, endpointContractVector);
