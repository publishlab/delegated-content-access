import { contentGroupsIssuerContribution } from "../../extensions/content-groups/core-issuer/unlock.js";
import type { IssuerContribution } from "../../integration-issuer/createIssuerCore.js";

// The assembly accepts the independently declared core contribution.
const contribution: IssuerContribution = contentGroupsIssuerContribution({
  policy: { decide: () => [] },
});
void contribution;
