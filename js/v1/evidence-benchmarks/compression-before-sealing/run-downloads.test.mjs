import assert from "node:assert/strict";
import test from "node:test";

import { articleBody } from "./run-downloads.js";

test("article extraction keeps a nested article inside the outer article", () => {
  const html = "<body>before<article>outer<article>inner</article>tail</article>after</body>";
  assert.equal(articleBody(html), "outer<article>inner</article>tail");
});
