import { contentGroupsIssuerContribution } from "../../extensions/content-groups/core-issuer/unlock.js";
import type { ResponseSectionSource } from "../../core-issuer/IssuerEngine.js";
import type { ComposedSection } from "../../core-shared--client-issuer/responseKeys.js";

const contribution = contentGroupsIssuerContribution({ policy: { decide: () => [] } });
const source: ResponseSectionSource = contribution.responseSectionSource;
const sections: readonly Readonly<ComposedSection>[] = contribution.responseSections;
contribution.requestBounds.forEach((bound) => bound({ toObject: () => ({}) }));
// @ts-expect-error the core result does not acquire arbitrary assembly members
contribution.invented();
void [source, sections];
