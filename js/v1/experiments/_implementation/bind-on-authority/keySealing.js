// @ts-check
// Sibling to base source: js/v1/core-shared--publisher-issuer/keySealing.js
//
// The authority-based BIND over the same ECDH and RSA carriers as core.

import { sealingWith } from "../../../tools/vector-fixtures/keySealingWith.js";
import { bindValue } from "./bind.js";

export const { seal, unseal } = sealingWith(bindValue);
