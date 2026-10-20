// @ts-check

// A child lane must be launched with the package manager that launched this
// process. npm sets `npm_execpath`; when that path is a JavaScript file (npm's
// own cli.js, or pnpm), it has to run under this Node binary rather than be
// executed directly, which covers Windows.

/**
 * @returns {{ command: string, commandArgs: string[] }}
 */
export function npmLauncher() {
  const launchedBy = process.env.npm_execpath;
  const fallback = process.platform === "win32" ? "npm.cmd" : "npm";
  if (launchedBy && /\.(?:c?js|mjs)$/.test(launchedBy)) {
    return { command: process.execPath, commandArgs: [launchedBy] };
  }
  if (launchedBy) return { command: launchedBy, commandArgs: [] };
  return { command: fallback, commandArgs: [] };
}
