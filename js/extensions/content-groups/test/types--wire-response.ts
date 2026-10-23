// Compiler-only consumer examples; no runtime or protocol requirements.
import type {
  ContentGroupResponse,
  ContentGroupChainKeys,
  ContentGroupPeriodKeys,
  ContentGroupContentKeys,
} from "../core-shared--client-issuer/request.js";
import type { StagedResponse } from "../core-client/contentGroupResponseInput.js";

const direct: ContentGroupResponse<string> = {
  chainKeys: [
    { contentName: "bodytext", group: "politics", cutoff: "261014T1800", key: "encoded-key" },
  ],
  periodKeys: [
    { contentName: "headline", group: "politics", period: "261014T1500", key: "encoded-key" },
  ],
  contentKeys: [{ contentName: "shoppingAd", key: "encoded-key" }],
  errors: {
    periodKeys: [
      { contentName: "headline", group: "sports", period: "261014T1500", error: "key_retired" },
    ],
  },
};

// Each record names its coordinates; no map level needs a positional reading.
for (const { contentName, group, cutoff, key } of direct.chainKeys ?? []) {
  const entry: { contentName: string; group: string; cutoff: string; key: string } = {
    contentName,
    group,
    cutoff,
    key,
  };
  void entry;
}

// A transport may protect key values with objects; errors keep fixed records.
const protectedResponse: ContentGroupResponse<{ encryptedKey: string }> = {
  contentKeys: [{ contentName: "shoppingAd", key: { encryptedKey: "protected-key" } }],
};
void protectedResponse;

const missingCutoff: ContentGroupChainKeys<string> = [
  // @ts-expect-error a chain record requires content name, group AND cutoff
  { contentName: "bodytext", group: "politics", key: "encoded-key" },
];
const periodAsCutoff: ContentGroupPeriodKeys<string> = [
  // @ts-expect-error a period record names its label `period`, not `cutoff`
  { contentName: "headline", group: "politics", cutoff: "261014T1500", key: "encoded-key" },
];
const wrongKey: ContentGroupPeriodKeys<string> = [
  // @ts-expect-error direct key values are strings, not numeric positions
  { contentName: "headline", group: "politics", period: "261014T1500", key: 6 },
];
const contentKeyGroup: ContentGroupContentKeys<string> = [
  // @ts-expect-error content keys name only their content name, no group
  { contentName: "shoppingAd", group: "shopping", key: "encoded-key" },
];
const wrongError: ContentGroupResponse<string> = {
  // @ts-expect-error errors are retirement records even for direct transport
  errors: { contentKeys: [{ contentName: "shoppingAd", error: "unseal_failed" }] },
};
const keyedError: ContentGroupResponse<string> = {
  // @ts-expect-error an error record carries no key
  errors: { contentKeys: [{ contentName: "shoppingAd", error: "key_retired", key: "k" }] },
};
const mapSection: ContentGroupResponse<string> = {
  // @ts-expect-error a section is an array of records, not a map by content name
  contentKeys: { shoppingAd: "encoded-key" },
};
void [missingCutoff, periodAsCutoff, wrongKey, contentKeyGroup, wrongError, keyedError, mapSection];

// Current processing already exposes named coordinates after wire staging.
// These entries still require key opening before they can be retained.
function stagedCoordinates(response: StagedResponse) {
  return response.chains.map(({ contentName, group, cutoffT }) => ({
    contentName,
    group,
    cutoffT,
  }));
}
void stagedCoordinates;

// Every field is a string: swapped values are structurally valid, not
// evidence that the server admitted that content name/group. Runtime
// admission owns that.
const swappedStrings: ContentGroupChainKeys<string> = [
  { contentName: "politics", group: "bodytext", cutoff: "261014T1800", key: "encoded-key" },
];
void swappedStrings;

// A section does not promise that a requested coordinate was returned.
function sparseLookup(
  chains: ContentGroupChainKeys<string>,
  response: ContentGroupResponse<string>,
) {
  const found = chains.find((r) => r.contentName === "bodytext" && r.group === "sports");
  // @ts-expect-error the record might be absent
  const uncheckedChain: string = found.key;
  // @ts-expect-error a response can omit the content-key section
  const uncheckedItems: ContentGroupContentKeys<string> = response.contentKeys;
  const safeChain: string | undefined = found?.key;
  const safeItem: string | undefined = response.contentKeys?.find(
    (r) => r.contentName === "bodytext",
  )?.key;
  void [uncheckedChain, uncheckedItems, safeChain, safeItem];
}
void sparseLookup;
