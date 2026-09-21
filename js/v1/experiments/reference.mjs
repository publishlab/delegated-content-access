// Optional public testing surface for alternate constructions. A consumer that
// needs only the standard reference imports ../reference.mjs and can omit this
// whole experiments directory.

export { bindValue as bindOnAccessGroup } from "./_implementation/bind-on-accessGroup/bind.js";
export {
  seal as sealOnAccessGroup,
  unseal as openOnAccessGroup,
} from "./_implementation/bind-on-accessGroup/keySealing.js";
