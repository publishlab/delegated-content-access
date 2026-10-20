// @ts-check
//
// This file holds the single placement contract that the markup writer and the
// markup reader share, per spec--data-format.md Section 3, markup delivery, and
// Section 5, the sealed-content carrier. The writer builds its elements from
// these tokens and the reader builds its selectors from the same tokens, so the
// two agree by construction on where each block goes. If each side spelled out
// the strings on its own, the two could drift apart.
//
// docs/spec--data-format.md Section 3 leaves order, depth and siblinghood free,
// so the contract covers only the two inert JSON script blocks and the class
// used to find each one. It says nothing about where in the body they land.
// A sealed blob is named inside the second block, as a JSON member, so no
// attribute and no per-item selector belongs here.

/** The class on the `<script type="application/json">` block carrying dca-data. */
export const DATA_CLASS = "dca-data";

/** The class on the `<script type="application/json">` block carrying the sealed blobs. */
export const SEALED_CLASS = "dca-sealed-content";

/** Found by class, per docs/spec--data-format.md Section 3: order, depth and siblinghood are free. */
export const DATA_SELECTOR = `.${DATA_CLASS}`;

/** The sealed-content block, likewise by class. */
export const SEALED_SELECTOR = `.${SEALED_CLASS}`;
