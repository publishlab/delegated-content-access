// @ts-check

// RFC 6750 bearer scheme and RFC 7235 b64token credential grammar. Consumers
// accept any scheme casing and one or more ASCII spaces after it.
/** @param {unknown} value @returns {string|null} */
export function parseBearerAuthorization(value) {
  if (typeof value !== "string") return null;
  const match = /^Bearer +([A-Za-z0-9._~+/-]+=*)$/i.exec(value);
  return match === null ? null : match[1];
}
