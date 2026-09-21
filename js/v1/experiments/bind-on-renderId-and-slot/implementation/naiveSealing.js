// @ts-check
// Sibling to base source: js/v1/core-shared--publisher-issuer/keySealing.js
//
// The naive join as a sealing: core's bound bodies, building the value with
// `naiveBindValue` - the delimiterless encoding
// `js/v1/core-shared--publisher-issuer/bind.js` rejected. It is the
// wiring the delimiter was written against, kept runnable so its defence can be
// run rather than described: a blob sealed here opens for a coordinate whose
// fields concatenate to the same bytes, where the shipped
// grammar's delimiter keeps `premium1|251023T13` and `premium|1251023T13` two
// strings.
//
// This sealing is named, and reached through the `keySealing` seam like
// `unboundSealing.js` beside it, rather than through a hook on the shipped core:
// hooking the core would put a security decision off the protocol path, so BIND
// stays on that path and an alternate binding lives in its own sealing.

import { sealingWith } from "../../../tools/vector-fixtures/keySealingWith.js";
import { naiveBindValue } from "./bind.js";

export const { seal, unseal } = sealingWith(naiveBindValue);
