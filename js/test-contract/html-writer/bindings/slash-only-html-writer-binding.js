// @ts-check
// Deliberately faulty writer: escaping slashes protects closing tags but leaves
// the <!-- <script transition active in the HTML tokenizer.

/** @param {unknown} value @returns {string} */
function slashOnly(value) {
  return JSON.stringify(value).replaceAll("/", "\\/");
}

export const dcaTestBinding = {
  targets: {
    "html-writer": {
      versions: ["1"],
      deliveryModes: ["markup"],
      contractProfiles: ["dca-profile-html-carrier"],
      observations: ["body-carrier-values-and-following-sentinel"],
      driver: {
        /** @param {import('../support/html-writer-contract.js').WriterInput} input */
        writeMarkup(input) {
          return (
            `<script type="application/json" class="dca-data">${slashOnly(input.dcaData)}</script>` +
            `<script type="application/json" class="dca-sealed-content">${slashOnly(input.sealedContent)}</script>`
          );
        },
      },
    },
  },
};
