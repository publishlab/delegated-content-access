import type { ContentGroupsPublisher } from "../../extensions/content-groups/integration-publisher/publisherTypes.js";
import {
  createPublisher,
  type PublisherEntryConfig,
  type Publisher,
} from "../../integration-publisher/createPublisher.js";
import {
  contentGroupsPublisherContribution,
  type ContentGroupsItemFields,
} from "../../extensions/content-groups/core-publisher/publish.js";

declare const config: PublisherEntryConfig;
const contribution = contentGroupsPublisherContribution({
  retainedSecret: new Uint8Array(32),
  periodGeometry: { chainsPerDay: 1, periodMinutes: 60 },
});
const base = createPublisher(config);
base.publish({
  resourceId: "article",
  data: {},
  items: [{ name: "body", value: "text", contentType: "text/plain" }],
});
base.publish({
  resourceId: "article",
  data: {},
  items: [
    {
      name: "body",
      value: new Uint8Array(),
      contentType: "application/octet-stream",
      accessGroups: ["news"],
    },
  ],
});
base.publish({
  resourceId: "article",
  data: {},
  items: [
    {
      name: "body",
      value: { bytes: new Uint8Array(), contentType: "text/plain", contentEncodings: [] },
    },
  ],
});
base.publish({
  resourceId: "article",
  data: {},
  // @ts-expect-error base publisher stays strict about extension fields
  items: [{ name: "body", value: "text", contentType: "text/plain", contentGroups: ["sports"] }],
});
base.publish({
  resourceId: "article",
  data: {},
  // @ts-expect-error misspelled base field
  items: [{ name: "body", value: "text", contentType: "text/plain", accessGroup: ["news"] }],
});
base.publish({
  resourceId: "article",
  data: {},
  items: [
    {
      name: "body",
      // @ts-expect-error descriptor has no sibling contentType
      value: { bytes: new Uint8Array(), contentType: "text/plain", contentEncodings: [] },
      contentType: "text/plain",
    },
  ],
});

// Explicit type declares selection; it does not prove contribution was supplied.
const groups: ContentGroupsPublisher = createPublisher(config, contribution);
groups.publish({
  resourceId: "article",
  data: {},
  items: [{ name: "body", value: "text", contentType: "text/plain", contentGroups: ["sports"] }],
});
groups.publish({
  resourceId: "article",
  data: {},
  items: [{ name: "body", value: new Uint8Array(), contentType: "text/plain", contentGroups: [] }],
});
groups.publish({
  resourceId: "article",
  data: {},
  items: [
    {
      name: "body",
      value: { bytes: new Uint8Array(), contentType: "text/plain", contentEncodings: [] },
      contentGroups: ["sports"],
    },
  ],
});
groups.publish({
  resourceId: "article",
  data: {},
  // @ts-expect-error selected field has a useful value contract
  items: [{ name: "body", value: "text", contentType: "text/plain", contentGroups: [123] }],
});
groups.publish({
  resourceId: "article",
  data: {},
  // @ts-expect-error selected publisher still refuses misspellings
  items: [{ name: "body", value: "text", contentType: "text/plain", contentGroup: ["sports"] }],
});
groups.publish({
  resourceId: "article",
  data: {},
  items: [
    {
      name: "body",
      // @ts-expect-error extension fields preserve descriptor sibling exclusion
      value: { bytes: new Uint8Array(), contentType: "text/plain", contentEncodings: [] },
      contentType: "text/plain",
      contentGroups: ["sports"],
    },
  ],
});
groups.publish({
  resourceId: "article",
  data: {},
  // @ts-expect-error required base content type remains required
  items: [{ name: "body", value: "text", contentGroups: ["sports"] }],
});

type OtherItemFields = { priority?: number };
// Two independently declared sets compose without a registry or inference.
const combined: Publisher<ContentGroupsItemFields & OtherItemFields> = createPublisher(
  config,
  contribution,
  { name: "priority", itemOptionMembers: ["priority"] },
);
combined.publish({
  resourceId: "article",
  data: {},
  items: [
    {
      name: "body",
      value: "text",
      contentType: "text/plain",
      contentGroups: ["sports"],
      priority: 2,
    },
  ],
});
combined.publish({
  resourceId: "article",
  data: {},
  items: [
    {
      name: "body",
      value: "text",
      contentType: "text/plain",
      contentGroups: ["sports"],
      // @ts-expect-error independently declared field is checked
      priority: "high",
    },
  ],
});
