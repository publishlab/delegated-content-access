// @ts-check

export const sections = [
  "setup",
  "samples",
  "captures",
  "sizes",
  "work",
  "timings",
  "cache",
  "checks",
  "summary",
];

// Human-facing carrier names; these labels are not added to captured wire JSON.
/** @type {Record<string, string>} */
const payloadLabels = {
  dcaData: "markup.dca-data",
  content: "markup.dca-sealed-content",
  request: "json.request",
  response: "json.response",
};

/** @param {string} show */
export function selectSections(show) {
  const names = show === "all" ? sections : show.split(",");
  if (names.length === 0 || names.some((name) => !sections.includes(name))) {
    throw new Error(`--show must name ${sections.join(", ")} or all`);
  }
  return names;
}

/** Presentation never executes a scenario or changes its checks.
 * @param {Record<string, any>} report
 * @param {{show?: string, detail?: string, format?: string}} [options]
 */
export function formatReport(report, { show, detail = "summary", format = "text" } = {}) {
  if (!["text", "json"].includes(format)) throw new Error("--format must be text or json");
  if (!["summary", "breakdown", "full"].includes(detail))
    throw new Error("--detail must be summary, breakdown or full");
  const names = selectSections(show ?? (format === "json" ? "all" : "sizes,checks"));
  const selected = {
    success: report.success,
    ...Object.fromEntries(names.map((name) => [name, report[name]])),
  };
  if (format === "json") return `${JSON.stringify(selected, null, 2)}\n`;
  const lines = [
    `${report.setup?.scenario ?? "Scenario bench"}: ${report.success ? "PASS" : "FAIL"}`,
  ];
  for (const name of names) {
    const value = report[name];
    if (name === "sizes" && detail === "summary") {
      if (report.samples?.length > 1)
        lines.push(
          `Wire sizes below are sample 1/${report.samples.length}; summary retains median/min/max across samples.`,
        );
      lines.push("payload                       JSON bytes   gzip bytes (level 9)");
      for (const capture of ["dcaData", "content", "request", "response"]) {
        const measured = value?.[capture];
        for (const [index, row] of (Array.isArray(measured) ? measured : [measured]).entries()) {
          const label = `${payloadLabels[capture]}${Array.isArray(measured) ? `[${index}]` : ""}`;
          lines.push(
            row && row.json !== undefined
              ? `${label.padEnd(29)} ${String(row.json).padStart(10)} ${String(row.gzip).padStart(12)}`
              : `${label}: unmeasured${row?.reason ? ` (${row.reason})` : ""}`,
          );
        }
      }
    } else if (name === "sizes") {
      const payloadSizes = Object.fromEntries(
        Object.entries(payloadLabels).map(([capture, label]) => [
          label,
          value?.[capture] ?? { available: false },
        ]),
      );
      lines.push(`sizes: ${JSON.stringify(payloadSizes, null, 2)}`);
    } else if (name === "captures") {
      const payloads = Object.fromEntries(
        Object.entries(payloadLabels).map(([capture, label]) => {
          const captured = value?.[capture];
          const payload = (/** @type {any} */ entry) =>
            entry?.document ?? entry ?? { available: false };
          return [label, Array.isArray(captured) ? captured.map(payload) : payload(captured)];
        }),
      );
      lines.push(`captures: ${JSON.stringify(payloads, null, 2)}`);
    } else if (name === "checks" && detail === "summary") {
      const samples = report.samples ?? [{ checks: value }];
      for (const [index, sample] of samples.entries()) {
        /** @type {{passed:boolean,name:string,details?:unknown}[]} */
        const checks = Array.isArray(sample.checks) ? sample.checks : [];
        lines.push(
          `checks${samples.length > 1 ? ` sample ${index + 1}` : ""}: ${checks.filter((check) => check.passed).length}/${checks.length} passed`,
        );
        for (const check of checks.filter((check) => !check.passed))
          lines.push(`  FAIL ${check.name}: ${JSON.stringify(check.details ?? "")}`);
      }
      for (const [index, sample] of (report.warmupSamples ?? []).entries()) {
        for (const check of sample.checks.filter(
          (/** @type {{passed:boolean,name:string,details?:unknown}} */ check) => !check.passed,
        ))
          lines.push(
            `  FAIL warmup ${index + 1} ${check.name}: ${JSON.stringify(check.details ?? "")}`,
          );
      }
    } else {
      lines.push(`${name}: ${JSON.stringify(value ?? { available: false }, null, 2)}`);
    }
  }
  return `${lines.join("\n")}\n`;
}
