#!/usr/bin/env node
// @ts-check
import { readFile, writeFile, mkdir, access } from "node:fs/promises";
import { resolve, join, dirname, relative, isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { runBench } from "./runBench.js";
import { formatReport, selectSections } from "./format.js";

const help = `Usage: node cli.js --scenario MODULE [options]

Run one resource through real DCA roles. Paths resolve from the current directory.
  --input FILE|-           JSON scenario input; '-' reads stdin
  --scope SCOPE            publisher | publisher-issuer | full (default)
  --runs N --warmup N      fresh measured samples (1) and diagnostic warmups (0)
  --time-steps             collect available named construction timings
  --count-crypto           isolated WebCrypto counts (module scenario required)
  --format text|json       stdout representation, default text
  --show SECTION,...|all   selected sections, never changes execution
  --detail summary|breakdown|full
  --out DIRECTORY         save full report and every sample's actual captures
  --save NAME=FILE         export report, section or singular wire capture
  --help                  show this help
`;

/** @param {string[]} args */
function parse(args) {
  /** @type {Record<string, string|boolean>} */
  const options = {};
  /** @type {{name:string,path:string}[]} */
  const saves = [];
  const valued = [
    "scenario",
    "input",
    "scope",
    "runs",
    "warmup",
    "format",
    "show",
    "detail",
    "out",
    "save",
  ];
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (!flag.startsWith("--")) throw new Error(`unexpected positional argument ${flag}`);
    const key = flag.slice(2);
    if (Object.hasOwn(options, key)) throw new Error(`duplicate option ${flag}`);
    if (["help", "time-steps", "count-crypto"].includes(key)) options[key] = true;
    else if (valued.includes(key)) {
      const value = args[++i];
      if (!value || value.startsWith("--")) throw new Error(`${flag} needs a value`);
      if (key === "save") {
        const split = value.indexOf("=");
        if (split < 1 || split === value.length - 1) throw new Error("--save needs NAME=FILE");
        saves.push({ name: value.slice(0, split), path: resolve(value.slice(split + 1)) });
      } else options[key] = value;
    } else throw new Error(`unknown option ${flag}`);
  }
  return { options, saves };
}

/** @param {string} path */
async function refuseOverwrite(path) {
  try {
    await access(path);
  } catch (error) {
    if (/** @type {NodeJS.ErrnoException} */ (error).code === "ENOENT") return;
    throw error;
  }
  throw new Error(`output already exists: ${path}; choose a fresh destination`);
}

/** @param {string} path @param {string} text */
async function save(path, text) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, text, { flag: "wx" });
}

/** @param {Record<string,any>} report @param {string} name */
function exported(report, name) {
  if (name === "report") return `${JSON.stringify(report, null, 2)}\n`;
  /** @type {Record<string,string>} */
  const aliases = {
    delivery: "delivery",
    "dca-data": "dcaData",
    request: "request",
    response: "response",
  };
  if (Object.hasOwn(aliases, name)) {
    if (report.samples.length !== 1)
      throw new Error("singular capture exports require exactly one measured run; use --out");
    const capture = report.captures[aliases[name]];
    if (!capture || capture.available === false) throw new Error(`capture ${name} is unavailable`);
    if (Array.isArray(capture))
      throw new Error(`capture ${name} contains several messages; use --out`);
    return capture.text;
  }
  if (!selectSections("all").includes(name)) throw new Error(`unknown --save section ${name}`);
  return `${JSON.stringify(report[name], null, 2)}\n`;
}

/** @param {Record<string,any>} report @param {string} output */
async function saveReport(report, output) {
  await mkdir(output, { recursive: true });
  await save(join(output, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  for (const [index, sample] of report.samples.entries()) {
    const sampleDir = join(output, `sample-${index + 1}`);
    for (const [name, captured] of Object.entries(sample.captures)) {
      const messages = Array.isArray(captured) ? captured : [captured];
      for (const [messageIndex, message] of messages.entries()) {
        if (!message || message.available === false) continue;
        // Capture identifiers are scenario-owned data, not filesystem paths.
        const file = join(`capture-${encodeURIComponent(name)}`, `${messageIndex + 1}.json`);
        await save(join(sampleDir, file), message.text);
      }
    }
  }
}

/** @param {string[]} [args] */
export async function main(args = process.argv.slice(2)) {
  const { options, saves } = parse(args);
  if (options.help) {
    process.stdout.write(help);
    return 0;
  }
  if (typeof options.scenario !== "string") throw new Error("--scenario MODULE is required");
  const format = String(options.format ?? "text");
  const detail = String(options.detail ?? "summary");
  const show = options.show === undefined ? undefined : String(options.show);
  // Validate presentation and destinations before performing measured work.
  formatReport({ success: true }, { format, detail, show });
  for (const { name } of saves)
    if (
      !["report", "delivery", "dca-data", "request", "response", ...selectSections("all")].includes(
        name,
      )
    )
      throw new Error(`unknown --save section ${name}`);
  const destinations = saves.map(({ path }) => path);
  if (new Set(destinations).size !== destinations.length)
    throw new Error("duplicate export destination");
  for (const path of destinations) await refuseOverwrite(path);
  const output = options.out === undefined ? undefined : resolve(String(options.out));
  if (output) {
    await refuseOverwrite(output);
    for (const path of destinations) {
      const within = relative(output, path);
      if (within === "" || (!within.startsWith("..") && !isAbsolute(within)))
        throw new Error("--save destination must be outside --out directory");
    }
  }
  if (
    Number(options.runs ?? 1) !== 1 &&
    saves.some(({ name }) => ["delivery", "dca-data", "request", "response"].includes(name))
  )
    throw new Error("singular capture exports require exactly one measured run; use --out");
  let input = {};
  if (typeof options.input === "string") {
    if (options.input === "-") {
      const chunks = [];
      for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
      input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } else input = JSON.parse(await readFile(resolve(options.input), "utf8"));
  }
  const scenarioUrl = pathToFileURL(resolve(options.scenario)).href;
  const { scenario } = await import(scenarioUrl);
  const measurement = {
    scope: /** @type {import("./runBench.js").Scope} */ (String(options.scope ?? "full")),
    runs: Number(options.runs ?? 1),
    warmup: Number(options.warmup ?? 0),
    timeSteps: options["time-steps"] === true,
    countCrypto: options["count-crypto"] === true,
  };
  const report = await runBench({ scenario, scenarioUrl, input, measurement });
  if (output) await saveReport(report, output);
  process.stdout.write(formatReport(report, { format, detail, show }));
  for (const { name, path } of saves) await save(path, exported(report, name));
  return report.success ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      process.stderr.write(`scenario-bench: ${error.message}\n`);
      process.exitCode = 1;
    });
}
