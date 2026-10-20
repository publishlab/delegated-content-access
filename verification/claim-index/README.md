# Scoped profile evidence

[`v1.json`](v1.json) records JavaScript reference support declarations,
deployment enablement, concrete evidence scenarios and the tests/packages tied
to each scenario. It reads profile names, dependencies, typed selections and
role duties from the checked [profile catalogue](../profile-catalogue/README.md);
it does not create another profile hierarchy or protocol authority.

The record separates five things:

- `subject` identifies the implementation and its declared roles.
- `support` describes role-specific supported alternatives and concrete
  compatible selections. Alternatives on separate roles do not imply every
  cross-product combination.
- `deploymentEnablement` is `null`: no deployment enablement is asserted.
- Each `scenario` gives requested profiles, exact typed selections, required
  duties, unresolved catalogue applicability, historical declarations/gaps,
  package references and test evidence selectors.
- `recordedPackages` is an inventory. Its checksum/recorder result establishes
  package integrity only; it never grants a role duty.

The record holds eight scenarios:

| Scenario                                                    | Scoped selection                                                           | Evidence limit kept in the record                                                                                                                                                                                     |
| ----------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `baseline-json-direct`                                      | Baseline JSON delivery                                                     | The serialized JSON path is tested, but baseline representation-processing evidence is missing from the selected identity; the recorded ECDH package proves envelope opening only.                                    |
| `period-keys-with-simulated-html-carrier`                   | Period-key route and HTML carrier                                          | Test evidence includes period-key delivery and replay; the carrier reads a simulated DOM, not a browser parser. Conditional role-duty applicability remains unresolved.                                               |
| `gzip-period-keys-with-simulated-html-carrier`              | Gzip item with period-key route and HTML carrier                           | Gzip composition is tested; no dedicated recorded gzip package, resource bound or strict one-member result is claimed.                                                                                                |
| `chain-period-projection-with-simulated-html-carrier`       | Chain input projected to a period key                                      | The client does not derive or receive chain output; the separate construction package is unmapped.                                                                                                                    |
| `chain-output-with-simulated-html-carrier`                  | Chain input and output with client derivation                              | The recorded prefix covers one geometry, window and cutoff and is JS regression/provenance evidence, not independent conformance.                                                                                     |
| `client-bound-ecdh-with-period-and-html-client-composition` | Client-bound ECDH with period-key and simulated-HTML client selections     | The integrated test also exercises a retained item key and simulated markup. Publisher setup is a test participant, not a credited scenario role. The selected combination remains incomplete in the tagged evidence. |
| `client-bound-rsa-with-period-and-html-client-composition`  | Client-bound RSA-OAEP with period-key and simulated-HTML client selections | The integrated test also exercises a retained item key and simulated markup. Publisher setup is a test participant, not a credited scenario role. The selected combination remains incomplete in the tagged evidence. |
| `html-carrier-in-simulated-dom`                             | HTML carrier                                                               | Markup is read through a simulated root and regex extraction; the base suite runs no browser or real HTML parser.                                                                                                     |

Scenario duties are resolved from the catalogue independently of evidence and
legacy declared-duty lists. Baseline duties for the scenario's roles remain
required. Optional duties without catalogue applicability metadata are listed
as `unresolvedApplicability`; neither a selected value nor a duty name is used
to guess applicability. Each projected duty must be accounted for as required
or unresolved, so a record cannot silently narrow the catalogue projection.

Evidence credit requires the exact scenario, test file and test name to match.
A matching test must pass and carry the recorded duty tag. Each scenario also
requires its named composition test to pass; separate role tests cannot replace
that witness. A pass from another
scenario, another test with the same tag, or a passing package checker cannot
fill that evidence slot. Skips, TODOs, failures and absent tests remain distinct.
The result `verified-in-scope` is limited to the selected catalogue projection;
it is not full normative conformance. The current records remain incomplete,
and the JavaScript reference makes no support claim here for browser-integration,
browser-origin or recipient-grant-unlock.

## Running the evidence commands

From `js/`, under Node 24.19 or newer:

```sh
pnpm run claim:evidence
pnpm run claim:all
```

`claim:evidence` runs the unique test files referenced by the eight scenarios.
`claim:all` observes every test admitted by `test:unit` but still credits only
exact scenario/test selectors. Both check the complete vector and fixture
package inventory and run each package's owning integrity check. Neither
invokes `verification/conformance-primitives/`; that independent stock-library
suite has its own inventory, driver and result.

The runner records the source revision and tracked working-tree state at run
time. If Git metadata is unavailable, it reports that fact rather than using a
fixed revision. The result reports support declarations separately from
scenario outcomes, leaves unasserted deployment enablement as `null`, and
lists catalogue profiles with no support declaration as `unclaimed`. Test
failures remain in the JSON report, including exact scenario failures; the
command exits nonzero after reporting if an observed test or integrity check
fails.
