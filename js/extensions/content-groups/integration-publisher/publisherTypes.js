// @ts-check

/**
 * Explicitly declare the selected composition at the publisher boundary:
 *
 *     const publisher: ContentGroupsPublisher = createPublisher(config, contribution);
 *     publisher.publish({ resourceId, data: {}, items: [
 *       { name: "body", value: "text", contentType: "text/plain", contentGroups: ["sports"] }
 *     ] });
 *
 * The annotation declares the integrator's selection; it cannot prove that
 * `contribution` is the matching runtime contribution. Supply it as well.
 * Additional independently owned fields compose through
 * `Publisher<ContentGroupsItemFields & OtherItemFields>`.
 * @typedef {import('../../../integration-publisher/createPublisher.js').Publisher<import('../core-publisher/publish.js').ContentGroupsItemFields>} ContentGroupsPublisher
 */

export {};
