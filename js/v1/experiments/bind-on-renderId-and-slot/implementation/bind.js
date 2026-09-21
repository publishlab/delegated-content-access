// @ts-check
// Sibling to base source: js/v1/core-shared--publisher-issuer/bind.js
//
// The encoding `js/v1/core-shared--publisher-issuer/bind.js` rejected, kept runnable so the break can be shown
// by running it. Same fields in the same order, joined with no boundary
// between them.
//
// What that costs: `premium1` with t `251023T13` and `premium` with t
// `1251023T13` come out as one string. The issuer never parses `t` - it takes
// both coordinates from the request member names it granted on and joins them -
// so it will build that string for a reader holding a `premium` grant, and open
// `premium1`'s periodKey with it.
//
// It joins `js/v1/core-shared--publisher-issuer/bind.js`'s own `bindFields`, so the delimiter is the only thing
// between this and the shipped value. A second field list here would let the
// two drift and turn the comparison into a comparison of two grammars.
//
// Nothing outside the tests reaches for this. `naiveSealing.js` beside it builds
// with this value, to show what the delimiter holds up, and it is one of the
// two wirings the boot self-test beside it has to tell apart from an attack.

import { bindFields } from "../../../core-shared--publisher-issuer/bind.js";

/**
 * @typedef {import('../../../core-shared--publisher-issuer/bind.js').Binding} Binding
 */

/**
 * @param {Binding} binding
 * @returns {string}
 */
export function naiveBindValue(binding) {
  return bindFields(binding).join("");
}
