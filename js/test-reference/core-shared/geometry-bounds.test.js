// @ts-check

import { portableTest } from "../support/portable-test.js";
import assert from "node:assert/strict";

import {
  inspectPeriodGeometryBounds,
  MAX_CHAIN_MEMBERS_PER_FAMILY,
  MAX_CHAIN_MEMBERS_PER_MESSAGE,
  MAX_PERIOD_KEYS_PER_FAMILY,
  MAX_PERIOD_KEYS_PER_RESPONSE,
  MAX_POSITIONS_PER_WINDOW,
  PERIOD_GEOMETRY_MINUTES_PER_DAY,
} from "../../core-shared/geometryBounds.js";
const portableCoreTest = portableTest("portable-core");

portableCoreTest("the shared geometry owner carries the frozen admission values", () => {
  assert.equal(PERIOD_GEOMETRY_MINUTES_PER_DAY, 1440);
  assert.equal(MAX_POSITIONS_PER_WINDOW, 288);
  assert.equal(MAX_CHAIN_MEMBERS_PER_FAMILY, 2);
  assert.equal(MAX_CHAIN_MEMBERS_PER_MESSAGE, 16);
  assert.equal(MAX_PERIOD_KEYS_PER_FAMILY, 288);
  assert.equal(MAX_PERIOD_KEYS_PER_RESPONSE, 512);
});

portableCoreTest("the numeric check distinguishes each refusal while admitting the ceiling", () => {
  assert.deepEqual(inspectPeriodGeometryBounds(7, 15), { kind: "invalidChainsPerDay" });
  assert.deepEqual(inspectPeriodGeometryBounds(2, 7), {
    kind: "invalidPeriodMinutes",
    windowMinutes: 720,
  });
  assert.deepEqual(inspectPeriodGeometryBounds(4, 1), {
    kind: "tooManyPositions",
    windowMinutes: 360,
    positionsPerWindow: 360,
  });
  assert.deepEqual(inspectPeriodGeometryBounds(5, 1), {
    kind: "valid",
    windowMinutes: 288,
    positionsPerWindow: 288,
  });
});
