// Stock geometry for normal content-group tests. Explicit fault ports stay in the tests that need them.
import {
  chainKeyCoordinate,
  chainKeyLabelAt,
  settleChainGeometry,
} from "../../../chain-keys/core-shared/chainKeyConstruction.js";

export const CHAIN = Object.freeze({
  settleGeometry: settleChainGeometry,
  coordinate: chainKeyCoordinate,
  labelAt: chainKeyLabelAt,
});
