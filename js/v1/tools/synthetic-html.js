// @ts-check
//
// Article-shaped content of about a wanted byte length, made up on the spot, in the
// three shapes a body takes.
//
// A benchmark that weighs content bytes needs input that looks like an article body and
// may be committed. Fetched pages fail both tests: they differ for whoever refetches
// them, and we may not redistribute them. This builds a seeded article model instead:
// paragraphs of made-up pronounceable words, some of them carrying a link, with an
// infobox between paragraphs. It renders that model three ways:
//
//   html   Parsoid-shaped markup, the fragment a bodytext field carries
//   txt    the same words as readable text
//   json   a structured body, `{"blocks":[{"type":"paragraph","spans":[...]}]}`, compact
//
// `syntheticArticle` grows the model until the asked-for form reaches the wanted length,
// then trims one paragraph span or one complete infobox row at a time, so every
// form approaches its own target. The same seed always gives the same bytes.
//
//     import { syntheticArticle } from './synthetic-html.js';
//     const body = syntheticArticle({ bytes: 10240, form: 'json' });
//
// The constants below were hand-tuned on 2026-09-10 against the four Wikipedia article
// bodies `evidence-benchmarks/compression-before-sealing/README.md` lists, whose html
// gzips at level 9 to between 0.22 and 0.41 of its length. At these settings the
// generated html gzips to 0.37 at 3 KB, 0.28 at 10 KB and 0.25 at 30 KB, which tracks
// pages of the same size within about a tenth. Treat the comparison as a sanity check;
// nothing here reproduces a particular page. Retune by running
// `evidence-benchmarks/compression-before-sealing/run-downloads.js` on the pages and
// then `run-synthetic.js` beside it. Only html was tuned; txt and json were left
// untuned.

/** How many made-up words the text draws on. A narrow vocabulary repeats. */
const VOCABULARY_WORDS = 800;

/** Rank weight falloff, following the shape of word frequencies in running text. */
const ZIPF_EXPONENT = 0.5;

/** The share of words carrying a link, which is most of the html markup. */
const LINK_DENSITY = 0.1;

/** Words per paragraph, drawn between these. */
const PARAGRAPH_WORDS = [30, 80];

/** Rows in one infobox. */
const INFOBOX_ROWS = 6;

/** An infobox lands between paragraphs this often. A long article repeats such
 * furniture, and gzip matches the repeats at long range. */
const BLOCK_EVERY = 2;

const CONSONANTS = "bcdfghjklmnprstvwz";
const VOWELS = "aeiouy";
const ID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/**
 * A run of words, carrying a link target when the run is a link.
 *
 * @typedef {{ text: string, href?: string, id?: string }} Span
 */

/**
 * One block of the body.
 *
 * @typedef {{ type: 'paragraph', id: string, spans: Span[] }
 *   | { type: 'infobox', id: string, section: number,
 *       rows: { label: string, value: string }[] }} Block
 */

/**
 * @param {number} seed
 * @returns {() => number} mulberry32, uniform in [0, 1)
 */
function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Pronounceable nonsense: one to three consonant-vowel syllables, sometimes
 * closed by a consonant.
 *
 * @param {number} size
 * @param {() => number} rng
 * @returns {string[]}
 */
function vocabulary(size, rng) {
  /** @type {Set<string>} */
  const words = new Set();
  while (words.size < size) {
    const syllables = 1 + Math.floor(rng() * 3);
    let word = "";
    for (let i = 0; i < syllables; i += 1) {
      word += CONSONANTS[Math.floor(rng() * CONSONANTS.length)];
      word += VOWELS[Math.floor(rng() * VOWELS.length)];
      if (rng() < 0.25) word += CONSONANTS[Math.floor(rng() * CONSONANTS.length)];
    }
    if (word.length > 1) words.add(word);
  }
  return [...words];
}

/**
 * @param {string[]} words
 * @param {() => number} rng
 * @returns {() => string} picks by rank with weight `1 / rank ** ZIPF_EXPONENT`
 */
function zipfPicker(words, rng) {
  const cumulative = new Float64Array(words.length);
  let total = 0;
  for (let i = 0; i < words.length; i += 1) {
    total += 1 / (i + 1) ** ZIPF_EXPONENT;
    cumulative[i] = total;
  }
  return () => {
    const target = rng() * total;
    let low = 0;
    let high = words.length - 1;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (cumulative[middle] < target) low = middle + 1;
      else high = middle;
    }
    return words[low];
  };
}

/**
 * @param {() => number} rng
 * @returns {string} a Parsoid-shaped node id
 */
function nodeId(rng) {
  let id = "mw";
  for (let i = 0; i < 3; i += 1) id += ID_CHARS[Math.floor(rng() * ID_CHARS.length)];
  return id;
}

/**
 * Add one block to the model, an infobox where one is due and a paragraph
 * otherwise.
 *
 * @param {Block[]} blocks
 * @param {() => string} pick
 * @param {() => number} rng
 */
function grow(blocks, pick, rng) {
  if (blocks.length > 0 && blocks.length % BLOCK_EVERY === 0) {
    const rows = [];
    for (let i = 0; i < INFOBOX_ROWS; i += 1) rows.push({ label: pick(), value: pick() });
    blocks.push({ type: "infobox", id: nodeId(rng), section: blocks.length, rows });
    return;
  }

  const count = PARAGRAPH_WORDS[0] + Math.floor(rng() * (PARAGRAPH_WORDS[1] - PARAGRAPH_WORDS[0]));
  /** @type {Span[]} */
  const spans = [];
  for (let i = 0; i < count; i += 1) {
    const text = pick();
    if (rng() < LINK_DENSITY) {
      const target = pick();
      spans.push({ text, href: `./${target[0].toUpperCase()}${target.slice(1)}`, id: nodeId(rng) });
    } else {
      spans.push({ text });
    }
  }
  blocks.push({ type: "paragraph", id: nodeId(rng), spans });
}

/**
 * Take the last part off the end of the model: one span of a paragraph, or one
 * row (label and value) of an infobox. The block goes with it when that part was
 * its last.
 *
 * @param {Block[]} blocks
 */
function trim(blocks) {
  const last = blocks[blocks.length - 1];
  if (last === undefined) return;
  const parts = last.type === "paragraph" ? last.spans : last.rows;
  parts.pop();
  if (parts.length === 0) blocks.pop();
}

/**
 * @param {Block[]} blocks
 * @returns {string}
 */
function asHtml(blocks) {
  return blocks
    .map((block) => {
      if (block.type === "infobox") {
        const rows = block.rows
          .map(
            ({ label, value }) =>
              `<tr><th class="infobox-label">${label}</th><td class="infobox-data">${value}</td></tr>`,
          )
          .join("");
        return (
          `<section data-mw-section-id="${block.section}" id="${block.id}">` +
          `<table class="infobox vevent"><tbody>${rows}</tbody></table></section>`
        );
      }
      const spans = block.spans
        .map((span) =>
          span.href === undefined
            ? span.text
            : `<a rel="mw:WikiLink" href="${span.href}" title="${span.href.slice(2)}" id="${span.id}">` +
              `${span.text}</a>`,
        )
        .join(" ");
      return `<p id="${block.id}">${spans}</p>`;
    })
    .join("\n");
}

/**
 * @param {Block[]} blocks
 * @returns {string}
 */
function asText(blocks) {
  return blocks
    .map((block) =>
      block.type === "infobox"
        ? block.rows.map(({ label, value }) => `${label} ${value}`).join(" ")
        : block.spans.map((span) => span.text).join(" "),
    )
    .join(" ");
}

/**
 * @param {Block[]} blocks
 * @returns {string}
 */
function asJson(blocks) {
  return JSON.stringify({
    blocks: blocks.map((block) =>
      block.type === "infobox"
        ? { type: "infobox", rows: block.rows }
        : {
            type: "paragraph",
            spans: block.spans.map((span) =>
              span.href === undefined ? { text: span.text } : { text: span.text, href: span.href },
            ),
          },
    ),
  });
}

const RENDERERS = { html: asHtml, txt: asText, json: asJson };

/**
 * One article body, rendered in the wanted form, at or just under the wanted length.
 *
 * @param {object} options
 * @param {number} options.bytes - how long the rendered form should be
 * @param {'html'|'txt'|'json'} [options.form]
 * @param {number} [options.seed] - the same seed always gives the same bytes
 * @returns {string}
 */
export function syntheticArticle({ bytes, form = "html", seed = 1 }) {
  const render = Object.hasOwn(RENDERERS, form) ? RENDERERS[form] : undefined;
  if (render === undefined) throw new Error(`unknown form ${form}`);

  const rng = mulberry32(seed);
  const pick = zipfPicker(vocabulary(VOCABULARY_WORDS, mulberry32(seed + 0x9e3779b9)), rng);

  /** @type {Block[]} */
  const blocks = [];
  while (Buffer.byteLength(render(blocks), "utf8") < bytes) grow(blocks, pick, rng);
  while (blocks.length > 0 && Buffer.byteLength(render(blocks), "utf8") > bytes) trim(blocks);
  return render(blocks);
}

/**
 * The tag-stripped form of an html fragment from outside this module: the five named
 * entities and numeric references decoded, whitespace collapsed to single spaces.
 *
 * @param {string} html
 * @returns {string}
 */
export function textOf(html) {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/&#x([0-9a-f]+);|&#(\d+);|&(lt|gt|quot|apos|amp);/gi, (_, hex, decimal, named) => {
      if (hex !== undefined) return String.fromCodePoint(parseInt(hex, 16));
      if (decimal !== undefined) return String.fromCodePoint(Number(decimal));
      return { lt: "<", gt: ">", quot: '"', apos: "'", amp: "&" }[named.toLowerCase()];
    })
    .replace(/\s+/g, " ")
    .trim();
}
