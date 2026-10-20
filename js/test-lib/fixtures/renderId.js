// @ts-check
//
// One renderId built the way the publisher builds it, for tests that need a
// renderId as input and not as the thing under test. It mirrors what
// core-publisher/Sealer.js draws at seal, base64url over RENDER_ID_BYTES bytes,
// and takes the byte count from that one exported constant so no test restates
// the number. The fill byte is the only thing a caller varies, to keep two
// incidental renderIds apart.

import { base64urlEncode } from "../../core-shared/codec.js";
import { RENDER_ID_BYTES } from "../../core-publisher/Sealer.js";

/**
 * @param {number} [fill] the byte every position carries. Only its being
 *   constant per renderId matters, so distinct fills give distinct renderIds.
 * @returns {string} a base64url renderId of RENDER_ID_BYTES bytes.
 */
export function makeRenderId(fill = 0x5a) {
  return base64urlEncode(new Uint8Array(RENDER_ID_BYTES).fill(fill));
}
