import {
  contentGroupsPublisherContribution,
  type ContentGroupsItemFields,
} from "../../extensions/content-groups/core-publisher/publish.js";
import type { ItemPreparation } from "../../core-publisher/Sealer.js";

const contribution = contentGroupsPublisherContribution({
  retainedSecret: new Uint8Array(32),
  periodGeometry: { chainsPerDay: 1, periodMinutes: 60 },
});
const preparation: ItemPreparation = contribution.itemPreparation;
const fields: ContentGroupsItemFields = { contentGroups: ["news"] };
// @ts-expect-error content-group names are strings
const badFields: ContentGroupsItemFields = { contentGroups: [123] };
void [preparation, fields, badFields];
