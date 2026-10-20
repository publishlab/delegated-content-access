import nodeTest from "node:test";

const selection = process.env.DCA_TEST_SELECTION;
if (selection !== undefined && selection.trim() === "") {
  throw new TypeError("DCA_TEST_SELECTION must be non-empty");
}

const noopTest = () => undefined;

export const test = selection === undefined ? nodeTest : noopTest;

export function portableTest(selectionName) {
  if (typeof selectionName !== "string" || selectionName.trim() === "") {
    throw new TypeError("selection name must be non-empty");
  }
  return selection === undefined || selection === selectionName ? nodeTest : noopTest;
}
