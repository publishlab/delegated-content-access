// @ts-check
//
// A headless Chromium harness for the HTML content-map evidence, per
// docs/spec-proposal--html-content-map.md Section 12.2. Every page the harness loads is
// answered by request interception at `https://pub.example/`, so no network
// is involved and the page origin is the publisher's signed origin:
//
// - `/article/<id>` and `/delivered/<id>` answer a page with
//   `Content-Security-Policy: script-src 'none'`. The parser runs with the
//   scripting flag set and no page script runs.
// - `/__harness` answers an empty page with no policy. Harness code runs in
//   that page's script context and reaches a locked page through a
//   same-origin iframe, so it never runs inside the locked page itself.
// - `/__js/<path>` answers the reference modules from this checkout, so
//   the browser client runs the same source the Node tests import.
//
// `DCA_ORACLE_BROWSER` names the browser executable; left unset, the harness
// looks for chrome-headless-shell in the puppeteer cache under the home
// directory. `DCA_ORACLE_BROWSER_LIBS` names a directory of extra runtime
// libraries (with `lib/x86_64-linux-gnu`, `usr/lib/x86_64-linux-gnu` and
// `etc/fonts` below it); left unset, `~/.cache/chrome-libs` is used when it
// exists. A missing executable makes the caller skip; a failed launch fails.
//
// Functions passed to `page.evaluate` run in the browser and reach its
// `document` through `globalThis`, because this file's lint scope has only
// Node globals.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const V1 = fileURLToPath(new URL("../../../", import.meta.url));
export const HARNESS_ORIGIN = "https://pub.example";
const CSP = "script-src 'none'";

/**
 * The browser executable the oracle runs, or null when none is installed.
 *
 * @returns {string|null}
 */
export function oracleBrowserPath() {
  const named = process.env.DCA_ORACLE_BROWSER;
  if (named) return existsSync(named) ? named : null;
  const cache = join(homedir(), ".cache", "puppeteer", "chrome-headless-shell");
  if (!existsSync(cache)) return null;
  for (const version of readdirSync(cache).sort().reverse()) {
    const candidate = join(
      cache,
      version,
      "chrome-headless-shell-linux64",
      "chrome-headless-shell",
    );
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/** @returns {Record<string, string>} */
function browserEnvironment() {
  const libs = process.env.DCA_ORACLE_BROWSER_LIBS ?? join(homedir(), ".cache", "chrome-libs");
  if (!existsSync(libs)) return { ...process.env };
  const libraryPath = [
    join(libs, "lib", "x86_64-linux-gnu"),
    join(libs, "usr", "lib", "x86_64-linux-gnu"),
    join(libs, "lib64"),
    process.env.LD_LIBRARY_PATH ?? "",
  ]
    .filter(Boolean)
    .join(":");
  return {
    ...process.env,
    LD_LIBRARY_PATH: libraryPath,
    FONTCONFIG_PATH: join(libs, "etc", "fonts"),
  };
}

/**
 * The canonical tree of a document, the form Section 7.2 observations read:
 * each node's kind, an element's local name and namespace, its attributes as
 * a sorted list of name-value pairs, and text and comment data. Template
 * contents appear under `content` so a change inside one is visible too.
 * Adjacent text nodes are joined into one. Serialization octets and attribute
 * order are not observed.
 *
 * The function runs inside the browser, so it uses no closure variables.
 *
 * @param {Document} document
 * @returns {any}
 */
function canonicalDocument(document) {
  /** @param {Node} node @returns {any} */
  const canon = (node) => {
    if (node.nodeType === 3) return { text: /** @type {Text} */ (node).data };
    if (node.nodeType === 8) return { comment: /** @type {Comment} */ (node).data };
    if (node.nodeType === 10) return { doctype: /** @type {DocumentType} */ (node).name };
    const element = /** @type {Element} */ (node);
    /** @type {any} */
    const out = {
      element: element.localName,
      ns: element.namespaceURI,
      attrs: Array.from(element.attributes)
        .map((a) => [a.namespaceURI ? `${a.namespaceURI}:${a.localName}` : a.name, a.value])
        .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)),
      children: canonList(element.childNodes),
    };
    if (element.localName === "template" && "content" in element) {
      out.content = canonList(/** @type {HTMLTemplateElement} */ (element).content.childNodes);
    }
    return out;
  };
  // A live DOM can hold adjacent text nodes, for example on both sides of a
  // removed element; the parser never builds them. Joining them lets a live
  // tree compare with a delivered form, and it changes no delivered form.
  /** @param {NodeListOf<ChildNode>} nodes @returns {any[]} */
  const canonList = (nodes) => {
    /** @type {any[]} */
    const out = [];
    for (const node of Array.from(nodes)) {
      const last = out[out.length - 1];
      if (node.nodeType === 3 && last !== undefined && "text" in last) {
        last.text += /** @type {Text} */ (node).data;
      } else {
        out.push(canon(node));
      }
    }
    return out;
  };
  return canonList(document.childNodes);
}

/**
 * Launch the oracle browser and open the harness page.
 *
 * @param {object} setup
 * @param {{ post: (url: string, request: object, context?: any) => Promise<any> }} [setup.transport] -
 *   the issuer transport the in-page browser client reaches through the
 *   exposed `dcaPost` binding
 */
export async function openOracle({ transport } = {}) {
  const executablePath = oracleBrowserPath();
  if (executablePath === null) throw new Error("no oracle browser is installed");
  const { default: puppeteer } = await import("puppeteer-core");
  const browser = await puppeteer.launch({
    executablePath,
    env: browserEnvironment(),
    args: ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
  });
  const version = await browser.version();

  /** @type {Map<string, string>} */
  const pages = new Map();
  let pageCount = 0;
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== HARNESS_ORIGIN) {
      void request.respond({ status: 404, body: "" });
      return;
    }
    if (url.pathname === "/__harness") {
      void request.respond({
        status: 200,
        contentType: "text/html; charset=utf-8",
        body: "<!DOCTYPE html><html><head><title>harness</title></head><body></body></html>",
      });
      return;
    }
    if (url.pathname.startsWith("/__js/")) {
      const file = join(V1, url.pathname.slice("/__js/".length));
      if (!file.startsWith(V1) || !existsSync(file)) {
        void request.respond({ status: 404, body: "" });
        return;
      }
      void request.respond({
        status: 200,
        contentType: "text/javascript; charset=utf-8",
        body: readFileSync(file, "utf8"),
      });
      return;
    }
    const html = pages.get(url.pathname);
    if (html === undefined) {
      void request.respond({ status: 404, body: "" });
      return;
    }
    void request.respond({
      status: 200,
      contentType: url.pathname.includes("legacy-encoding")
        ? "text/html; charset=windows-1252"
        : "text/html; charset=utf-8",
      headers: { "Content-Security-Policy": CSP },
      body: html,
    });
  });
  if (transport !== undefined) {
    await page.exposeFunction(
      "dcaPost",
      async (/** @type {string} */ url, /** @type {any} */ request) =>
        transport.post(url, request, { origin: HARNESS_ORIGIN }),
    );
  }
  await page.goto(`${HARNESS_ORIGIN}/__harness`, { waitUntil: "load" });

  /**
   * Serve `html` under the policy and load it into a fresh iframe of the
   * harness page. Returns the iframe's index in the harness page.
   *
   * @param {string} kind - `article` or `delivered`
   * @param {string} html
   * @returns {Promise<number>}
   */
  async function load(kind, html) {
    pageCount += 1;
    const path = `/${kind}/${pageCount}`;
    pages.set(path, html);
    return page.evaluate(async (/** @type {string} */ src) => {
      const frame = globalThis.document.createElement("iframe");
      const loaded = new Promise((resolve) => frame.addEventListener("load", resolve));
      frame.src = src;
      globalThis.document.body.append(frame);
      await loaded;
      return globalThis.document.querySelectorAll("iframe").length - 1;
    }, path);
  }

  return {
    version,

    /**
     * Run the browser client of the profile inside Chromium on one locked page.
     *
     * @param {string} html - the locked delivery
     * @param {object} [options]
     * @param {object} [options.limits]
     * @returns {Promise<{ report: any, reconstructed: boolean, targets: any[], serialized: string, live: any, error: string|null }>}
     */
    async runBrowserClient(html, options = {}) {
      const frameIndex = await load("article", html);
      return page.evaluate(
        async (
          /** @type {number} */ index,
          /** @type {string} */ issuerName,
          /** @type {any} */ limits,
          /** @type {string} */ canonicalSource,
        ) => {
          const canonical = new Function(`return ${canonicalSource}`)();
          const frame = /** @type {HTMLIFrameElement} */ (
            globalThis.document.querySelectorAll("iframe")[index]
          );
          const locked = /** @type {Document} */ (frame.contentDocument);
          const { reconstructBrowserPage } =
            await import("/__js/extensions/html-content-map/integration-client/reconstructBrowserPage.js");
          const { serializeDomDocument } =
            await import("/__js/extensions/html-content-map/adapter-client/domTree.js");
          try {
            const result = await reconstructBrowserPage({
              unlockUrl: "https://issuer.example/unlock",
              document: locked,
              isEligible: () => frame.isConnected && frame.contentDocument === locked,
              issuerName,
              transport: {
                post: async (/** @type {string} */ url, /** @type {object} */ request) =>
                  /** @type {any} */ (globalThis).dcaPost(url, request),
              },
              ...(limits === null ? {} : { limits }),
            });
            return {
              ...result,
              serialized: serializeDomDocument(locked),
              live: canonical(locked),
              error: null,
            };
          } catch (cause) {
            return {
              report: null,
              reconstructed: false,
              targets: [],
              serialized: serializeDomDocument(locked),
              live: canonical(locked),
              error: String(/** @type {any} */ (cause)?.code ?? cause),
            };
          }
        },
        frameIndex,
        "map_issuer",
        options.limits ?? null,
        canonicalDocument.toString(),
      );
    },

    /**
     * The oracle harness of Section 12.2: apply the rules to the locked page
     * with `querySelectorAll`, the `innerHTML` and `textContent` setters,
     * `classList.remove` and `remove()`, from the harness page's script
     * context, then serialize with the delivery carrier retained. It uses none of the
     * reference's content-map code.
     *
     * @param {string} html - the locked delivery
     * @param {{ rules: any[] }} map
     * @param {Record<string, string>} opened - the text of each opened item
     * @returns {Promise<{ serialized: string, live: any, counts: number[], paths: (number[]|null)[] }>}
     */
    async applyOracle(html, map, opened) {
      const frameIndex = await load("article", html);
      return page.evaluate(
        (
          /** @type {number} */ index,
          /** @type {any} */ contentMap,
          /** @type {Record<string, string>} */ texts,
          /** @type {string} */ canonicalSource,
        ) => {
          const canonical = new Function(`return ${canonicalSource}`)();
          const frame = /** @type {HTMLIFrameElement} */ (
            globalThis.document.querySelectorAll("iframe")[index]
          );
          const locked = /** @type {Document} */ (frame.contentDocument);
          // The item records, by the contentName each carries; the last
          // record under a name wins, as a reader resolves it.
          const contentData = Object.fromEntries(
            (
              JSON.parse(locked.querySelector(".dca-data")?.textContent ?? "{}").contentData ?? []
            ).map((/** @type {any} */ record) => [record.contentName, record]),
          );
          const targets = contentMap.rules.map((/** @type {any} */ rule) =>
            Array.from(locked.querySelectorAll(rule.target)),
          );
          // Section 7.2 names a target by its element-child indexes from the
          // document element, taken in the locked document before any change.
          const paths = targets.map((/** @type {Element[]} */ found) => {
            if (found.length !== 1) return null;
            /** @type {number[]} */
            const path = [];
            for (let at = found[0]; at !== locked.documentElement;) {
              const parent = /** @type {Element} */ (at.parentElement);
              path.unshift(Array.from(parent.children).indexOf(at));
              at = parent;
            }
            return path;
          });
          contentMap.rules.forEach((/** @type {any} */ rule, /** @type {number} */ i) => {
            if (!Object.hasOwn(texts, rule.item) || targets[i].length !== 1) return;
            const target = /** @type {Element} */ (targets[i][0]);
            if (rule.op === "remove") target.remove();
            else if (rule.op === "removeClass") target.classList.remove(rule.class);
            else if (contentData[rule.item].contentType === "text/plain") {
              target.textContent = texts[rule.item];
            } else target.innerHTML = texts[rule.item];
          });
          let serialized = "";
          for (const node of Array.from(locked.childNodes)) {
            if (node.nodeType === 10)
              serialized += `<!DOCTYPE ${/** @type {DocumentType} */ (node).name}>`;
            else if (node.nodeType === 1) serialized += /** @type {Element} */ (node).outerHTML;
            else if (node.nodeType === 8)
              serialized += `<!--${/** @type {Comment} */ (node).data}-->`;
          }
          return {
            serialized,
            live: canonical(locked),
            counts: targets.map((/** @type {Element[]} */ found) => found.length),
            paths,
          };
        },
        frameIndex,
        map,
        opened,
        canonicalDocument.toString(),
      );
    },

    /**
     * The delivered form of a serialization (Section 7.1): the tree Chromium
     * builds when it loads the text as a page under the same policy.
     *
     * @param {string} serialized
     * @returns {Promise<any>}
     */
    async deliveredForm(serialized) {
      const frameIndex = await load("delivered", serialized);
      return page.evaluate(
        (/** @type {number} */ index, /** @type {string} */ canonicalSource) => {
          const canonical = new Function(`return ${canonicalSource}`)();
          const frame = /** @type {HTMLIFrameElement} */ (
            globalThis.document.querySelectorAll("iframe")[index]
          );
          return canonical(/** @type {Document} */ (frame.contentDocument));
        },
        frameIndex,
        canonicalDocument.toString(),
      );
    },

    /**
     * Whether a script in a page served by the harness would run: loads a
     * page with an inline script under the policy and reports whether it ran.
     *
     * @returns {Promise<{ scriptRan: boolean, compatMode: string }>}
     */
    async policyProbe() {
      const frameIndex = await load(
        "article",
        "<!DOCTYPE html><html><body><noscript><p>x</p></noscript><script>window.__ran = true</script></body></html>",
      );
      return page.evaluate((/** @type {number} */ index) => {
        const frame = /** @type {HTMLIFrameElement} */ (
          globalThis.document.querySelectorAll("iframe")[index]
        );
        const win = /** @type {any} */ (frame.contentWindow);
        const doc = /** @type {Document} */ (frame.contentDocument);
        return {
          scriptRan: win.__ran === true,
          compatMode: doc.compatMode,
          noscriptChildren: /** @type {Element} */ (doc.querySelector("noscript")).children.length,
        };
      }, frameIndex);
    },

    /** A real connected callback must not hide collateral changes in success.
     * @param {'text'|'attribute'|'fill'|'doctype'} mode @returns {Promise<any>}
     */
    async placementBoundaryProbe(mode) {
      const map = {
        version: "1",
        rules: [
          { item: "a", op: "fill", target: "#slot" },
          { item: "a", op: "removeClass", target: "#slot", class: "locked" },
        ],
      };
      const index = await load(
        "article",
        `<!doctype html><html><body><div id="slot" class="locked">teaser</div><aside id="other">original</aside><script class="dca-data" type="application/json">${JSON.stringify({ contentMap: map })}</script></body></html>`,
      );
      return page.evaluate(
        async (index, mode) => {
          const frame = /** @type {HTMLIFrameElement} */ (
            globalThis.document.querySelectorAll("iframe")[index]
          );
          const win = /** @type {any} */ (frame.contentWindow);
          const doc = /** @type {Document} */ (frame.contentDocument);
          win.customElements.define(
            "article-widget",
            class extends win.HTMLElement {
              connectedCallback() {
                if (mode === "text") doc.querySelector("#other").textContent = "collateral";
                else if (mode === "attribute")
                  doc.querySelector("#other").setAttribute("data-changed", "collateral");
                else if (mode === "doctype")
                  doc.replaceChild(
                    doc.implementation.createDocumentType(
                      "html",
                      "changed-public-id",
                      "changed-system-id",
                    ),
                    doc.doctype,
                  );
                else this.textContent = "unexpected fill";
              }
            },
          );
          const { domTree } =
            await import("/__js/extensions/html-content-map/adapter-client/domTree.js");
          const { createContentMapSession } =
            await import("/__js/extensions/html-content-map/core-client/contentMapRun.js");
          const client = {
            dcaData: {
              contentItemFor: (/** @type {string} */ contentName) => ({
                contentName,
                contentType: "text/html",
                contentEncodings: [],
                nonce: "",
                contentAad: new Uint8Array(0),
              }),
            },
            reader: { extract: () => "QUJD" },
            resolver: {
              resolveDetailed: async () => ({ missing: [] }),
              resolveAuthenticated: async () => ({ covered: [], missing: [], origins: [] }),
            },
            opener: {
              open: async () =>
                new TextEncoder().encode("<article-widget>prepared</article-widget>"),
            },
            unlock: async () => {},
          };
          const session = createContentMapSession({
            tree: domTree(doc),
            delivery: {
              declares: () => true,
              carriesCiphertext: () => true,
              contentType: () => "text/html",
            },
            keyClient: () => client,
          });
          const result = await session.run();
          return {
            report: result.report,
            locked: doc.querySelector("#slot").classList.contains("locked"),
            targetHtml: doc.querySelector("#slot").innerHTML,
          };
        },
        index,
        mode,
      );
    },

    /** @returns {Promise<any>} */
    async encodingProbe() {
      const index = await load(
        "legacy-encoding",
        "<!doctype html><html><body><div>ASCII source under a legacy encoding</div></body></html>",
      );
      return page.evaluate(async (index) => {
        const frame = /** @type {HTMLIFrameElement} */ (
          globalThis.document.querySelectorAll("iframe")[index]
        );
        const doc = /** @type {Document} */ (frame.contentDocument);
        const { createBrowserMapSession } =
          await import("/__js/extensions/html-content-map/integration-client/reconstructBrowserPage.js");
        const session = createBrowserMapSession({
          document: doc,
          isEligible: () => true,
          issuerName: "unused",
          transport: {
            post: async () => {
              throw new Error("must not acquire");
            },
          },
        });
        return { encoding: doc.characterSet, result: await session.run() };
      }, index);
    },

    close: () => browser.close(),
  };
}
