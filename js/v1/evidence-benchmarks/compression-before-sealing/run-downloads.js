// @ts-check
//
// This script runs the same measurement on real pages, to check that the synthetic
// bodies compress about as well as article html does.
//
// Run it from the repository root. With no argument it fetches the four pages
// `README.md` lists; arguments replace that list and may be any mix of http(s) URLs
// and local paths:
//
//     node js/v1/evidence-benchmarks/compression-before-sealing/run-downloads.js
//
// The script downloads each page into a fresh directory under the OS temp directory,
// extracts its article body, writes it there for inspection, and measures it through
// `measure.js` in the two forms a real page provides: the html fragment and its
// readable text. A json form comes only from the generator, so a downloaded page has
// no json row.
//
// Nothing is written into the repository. Fetched text differs for whoever refetches
// it and we may not redistribute it, so `run-synthetic.js` generates its own input
// instead.
//
// The body is the inner HTML of the first `<article>` element, or of `<body>` when the
// page has no article, or the whole page when it has neither. Script, style, noscript
// and svg elements are removed with their contents, and so are HTML comments. The
// extraction deliberately uses regular expressions: this script weighs the bytes of a
// page rather than rendering it.
//
// A Wikipedia article changes between refetches, so the script prints a pinned URL
// beside each page. The REST endpoint accepts a revision as a last path segment, and
// the unpinned response carries its revision in the `ETag` header. `README.md` lists
// the same four pinned URLs beside the bytes measured from them.

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";

import { textOf } from "../../tools/synthetic-html.js";
import { measureSample, table } from "./measure.js";

/**
 * The pages the generator was last checked against, pinned to the revisions listed
 * in `README.md`, so a bare run refetches those exact bytes.
 */
const DEFAULT_PAGES = [
  "https://no.wikipedia.org/api/rest_v1/page/html/Sursild/25833098",
  "https://no.wikipedia.org/api/rest_v1/page/html/R%C3%B8mmegr%C3%B8t/23941856",
  "https://en.wikipedia.org/api/rest_v1/page/html/Sodd/1327060023",
  "https://no.wikipedia.org/api/rest_v1/page/html/Sitron/25828561",
];

/** Wikimedia asks every automated client to name itself and leave a contact. */
const USER_AGENT = "dca-compression-before-sealing-benchmark/1.0 (contact: dca-benchmark)";

/**
 * @param {string} source - an http(s) URL or a local file path
 * @returns {Promise<{ html: string, revision: string | null }>}
 */
async function download(source) {
  if (/^https?:\/\//i.test(source)) {
    const response = await fetch(source, { headers: { "user-agent": USER_AGENT } });
    if (!response.ok) throw new Error(`${source} answered ${response.status}`);
    const etag = /W\/"(\d+)\//.exec(response.headers.get("etag") ?? "");
    return { html: await response.text(), revision: etag ? etag[1] : null };
  }
  return { html: readFileSync(resolve(source), "utf8"), revision: null };
}

/**
 * The Wikipedia language and article title behind a URL, when the source is one.
 *
 * @param {string} source
 * @returns {{ language: string, title: string } | null}
 */
function wikipediaArticle(source) {
  if (!/^https?:\/\//i.test(source)) return null;
  const { hostname, pathname } = new URL(source);
  const host = /^([a-z]{2,3}(?:-[a-z]+)?)\.wikipedia\.org$/i.exec(hostname);
  if (!host) return null;
  const segments = pathname.split("/").filter((segment) => segment.length > 0);
  if (segments.length === 0) return null;
  // When a URL ends in its revision, the title is the segment before it.
  const last = segments[segments.length - 1];
  const title = /^\d+$/.test(last) && segments.length > 1 ? segments[segments.length - 2] : last;
  return { language: host[1].toLowerCase(), title: decodeURIComponent(title) };
}

/**
 * @param {string} name
 * @returns {string} lowercase, ascii, single dashes. The Norwegian letters that
 *   the ASCII fold does not handle are spelled out before normalization.
 */
function dashed(name) {
  return name
    .replace(/[æÆ]/g, "ae")
    .replace(/[øØ]/g, "o")
    .replace(/[åÅ]/g, "a")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * A label for one page: a Wikipedia article by language and title, anything else
 * by its last URL segment or file name.
 *
 * @param {string} source
 * @returns {string}
 */
function labelOf(source) {
  const article = wikipediaArticle(source);
  if (article) return `${article.language}-${dashed(article.title)}`;

  let name = source;
  if (/^https?:\/\//i.test(source)) {
    const { hostname, pathname } = new URL(source);
    const segments = pathname.split("/").filter((segment) => segment.length > 0);
    name = segments.length > 0 ? segments[segments.length - 1] : hostname;
  } else {
    name = basename(source);
  }
  const label = dashed(name.replace(/\.[a-z0-9]+$/i, ""));
  return label.length > 0 ? label : "page";
}

/**
 * @param {string} html - a whole page
 * @returns {string} the inner HTML of the first `<article>`, else of `<body>`,
 *   else the page as given, with comments and inert elements removed
 */
export function articleBody(html) {
  const articleStart = /<article\b[^>]*>/i.exec(html);
  let article = null;
  if (articleStart) {
    const tags = /<\/?article\b[^>]*>/gi;
    tags.lastIndex = articleStart.index;
    let depth = 0;
    let tag;
    while ((tag = tags.exec(html))) {
      if (/^<\//.test(tag[0])) depth -= 1;
      else depth += 1;
      if (depth === 0) {
        article = [tag[0], html.slice(articleStart.index + articleStart[0].length, tag.index)];
        break;
      }
    }
  }
  const body = article ?? /<body\b[^>]*>([\s\S]*?)<\/body\s*>/i.exec(html);
  return (body ? body[1] : html)
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style|noscript|svg)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<(script|style|noscript|svg)\b[^>]*\/>/gi, "")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

async function main() {
  const given = process.argv.slice(2);
  const sources = given.length > 0 ? given : DEFAULT_PAGES;

  const directory = mkdtempSync(join(tmpdir(), "dca-compression-"));

  /** @type {import('./measure.js').Row[]} */
  const rows = [];
  /** @type {string[]} */
  const pages = [];

  for (const source of sources) {
    const { html, revision } = await download(source);
    const body = articleBody(html);
    const label = labelOf(source);
    const bare = source.replace(/\/+$/, "");
    const pinned =
      wikipediaArticle(source) && revision && !bare.endsWith(`/${revision}`)
        ? `${bare}/${revision}`
        : bare;

    const text = textOf(body);
    writeFileSync(join(directory, `${label}.html`), body, "utf8");
    writeFileSync(join(directory, `${label}.txt`), text, "utf8");
    pages.push(`${label}: ${Buffer.byteLength(body, "utf8")} html bytes, ${pinned}`);

    rows.push(...(await measureSample({ label, form: "html", bytes: body })));
    rows.push(...(await measureSample({ label, form: "txt", bytes: text })));
  }

  process.stdout.write(`${pages.join("\n")}\nBodies written to ${directory}\n\n${table(rows)}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) await main();
