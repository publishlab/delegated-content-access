// Static-tool evidence; absence of completed work never means success.
import { spawnSync } from "node:child_process";
import process from "node:process";
import console from "node:console";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { resolve, join } from "node:path";

const marker = "DCA type evidence: ";
export function classifyTypes(text, status) {
  const rows = text.split("\n").filter((line) => line.startsWith(marker));
  if (rows.length !== 1) return "PART";
  let evidence;
  try {
    evidence = JSON.parse(rows[0].slice(marker.length));
  } catch {
    return "PART";
  }
  if (
    evidence.complete !== true ||
    !Number.isSafeInteger(evidence.files) ||
    evidence.files < 5 ||
    !Number.isSafeInteger(evidence.diagnostics) ||
    evidence.diagnostics < 0
  )
    return "PART";
  if (status === 1 && evidence.diagnostics > 0) return "FAIL";
  return status === 0 && evidence.diagnostics === 0 ? "PASS" : "PART";
}

function types() {
  const config = JSON.parse(readFileSync("jsconfig.json", "utf8"));
  const required = config.include.map((file) => resolve(file));
  const run = spawnSync(
    "../../node_modules/.bin/tsc",
    ["-p", "jsconfig.json", "--pretty", "false", "--listFiles"],
    { encoding: "utf8" },
  );
  const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
  process.stdout.write(output);
  const files = new Set();
  const diagnostics = [];
  let unexplained = false;
  let inDiagnostic = false;
  for (const raw of output.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const diagnostic = /^(.*)\(\d+,\d+\): error TS\d+: /.exec(line);
    if (diagnostic && /\.(?:[cm]?[jt]sx?)$/.test(diagnostic[1]) && existsSync(diagnostic[1])) {
      diagnostics.push(diagnostic);
      inDiagnostic = true;
    } else if (existsSync(line)) {
      files.add(resolve(line));
      inDiagnostic = false;
    } else if (!(inDiagnostic && /^\s{2,}\S/.test(raw))) unexplained = true;
  }
  const evidence = {
    files: files.size,
    diagnostics: diagnostics.length,
    complete:
      !run.error &&
      !run.signal &&
      !unexplained &&
      required.length === 5 &&
      required.every((file) => files.has(file)),
  };
  console.log(`${marker}${JSON.stringify(evidence)}`);
  const verdict = classifyTypes(`${marker}${JSON.stringify(evidence)}`, run.status);
  process.exit(verdict === "PASS" ? 0 : verdict === "FAIL" ? 1 : 2);
}

async function format() {
  const prettier = await import("../../node_modules/prettier/index.mjs");
  const files = [];
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (["node_modules", ".git"].includes(entry.name)) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (/\.(?:js|mjs|json|md)$/.test(entry.name)) files.push(path);
    }
  }
  visit(".");
  let failed = 0;
  for (const file of files) {
    const config = await prettier.resolveConfig(file, { config: "../../.prettierrc.json" });
    if (!(await prettier.check(readFileSync(file, "utf8"), { ...config, filepath: file }))) {
      console.log(`format differs: ${file}`);
      failed++;
    }
  }
  console.log(`DCA formatting evidence: ${JSON.stringify({ files: files.length, failed })}`);
  process.exit(failed ? 1 : 0);
}

if (process.argv[2] === "types") types();
else if (process.argv[2] === "format") await format();
else if (process.argv[2] === "classify-types")
  console.log(classifyTypes(readFileSync(process.argv[3], "utf8"), Number(process.argv[4])));
else throw new Error("usage: static-evidence.mjs types|format|classify-types LOG STATUS");
