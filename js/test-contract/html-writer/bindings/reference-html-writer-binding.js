// @ts-check
import { writeMarkupDelivery } from "../../../adapter-publisher/writeMarkupDelivery.js";

/** @type {import('../support/html-writer-contract.js').HtmlWriterDriver} */
const driver = {
  writeMarkup({ dcaData, sealedContent }) {
    return writeMarkupDelivery({
      dcaData,
      sealedContent: Object.fromEntries(
        sealedContent.map(({ contentName, content }) => [contentName, content]),
      ),
    });
  },
};

export const dcaTestBinding = {
  targets: {
    "html-writer": {
      versions: ["1"],
      deliveryModes: ["markup"],
      contractProfiles: ["dca-profile-html-carrier"],
      observations: ["body-carrier-values-and-following-sentinel"],
      driver,
    },
  },
};
