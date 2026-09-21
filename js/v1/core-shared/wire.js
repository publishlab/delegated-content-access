// @ts-check
//
// Own-property lookup over wire-derived objects. `map[name]` reaches
// Object.prototype, so 'constructor' resolves to a function rather than missing.

/**
 * @param {any} map
 * @param {string} key
 * @returns {any}
 */
export function own(map, key) {
  if (map === null || typeof map !== "object") return undefined;
  return Object.hasOwn(map, key) ? map[key] : undefined;
}

/**
 * Write `name` as an own enumerable member. `map[name] = value` runs the setter
 * on Object.prototype for `__proto__` and moves the map's prototype instead of
 * adding a member. Defining an own property gives every admitted name the same
 * behavior, including names inherited by ordinary objects.
 *
 * @param {Record<string, any>} map
 * @param {string} name
 * @param {any} value
 */
export function setOwn(map, name, value) {
  Object.defineProperty(map, name, { value, writable: true, enumerable: true, configurable: true });
}
