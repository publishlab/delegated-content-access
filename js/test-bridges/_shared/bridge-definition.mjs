import { resolve } from "node:path";

/**
 * The worker starts `command [...arguments, adapter]` in `adapterCwd`, which
 * defaults to the current directory. `adapter` is a script path for an
 * interpreter; a compiled adapter gives `command` alone. `targetRoot` names the
 * test target's own tree and has no default: an adapter that loads no files
 * from a root leaves it unset.
 *
 * @param {{ id: string, adapter?: string, adapterCwd?: string, targetRoot?: string, command?: string, arguments?: string[] }} value
 */
export function defineBridge(value) {
  if (!value || typeof value !== "object") throw new TypeError("bridge definition is an object");
  if (!/^[a-z][a-z0-9-]*$/.test(value.id)) throw new TypeError("bridge id is lowercase kebab-case");
  if (
    value.adapter !== undefined &&
    (typeof value.adapter !== "string" || value.adapter.length === 0)
  )
    throw new TypeError("bridge adapter is a module path");
  if (
    value.command !== undefined &&
    (typeof value.command !== "string" || value.command.length === 0)
  )
    throw new TypeError("bridge command is a string");
  if (value.adapter === undefined && value.command === undefined)
    throw new TypeError("bridge definition names a command or an adapter");
  if (
    value.adapterCwd !== undefined &&
    (typeof value.adapterCwd !== "string" || value.adapterCwd.length === 0)
  )
    throw new TypeError("bridge adapter working directory is a directory path");
  if (
    value.targetRoot !== undefined &&
    (typeof value.targetRoot !== "string" || value.targetRoot.length === 0)
  )
    throw new TypeError("bridge target root is a directory path");
  if (
    value.arguments !== undefined &&
    (!Array.isArray(value.arguments) || !value.arguments.every((x) => typeof x === "string"))
  )
    throw new TypeError("bridge arguments are strings");
  return Object.freeze({
    id: value.id,
    adapter: value.adapter === undefined ? undefined : resolve(value.adapter),
    adapterCwd: resolve(value.adapterCwd ?? process.cwd()),
    targetRoot: value.targetRoot === undefined ? undefined : resolve(value.targetRoot),
    command: value.command ?? process.execPath,
    arguments: Object.freeze(value.arguments ?? []),
  });
}
