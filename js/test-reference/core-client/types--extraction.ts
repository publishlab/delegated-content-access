import { ContentGroupRequestBuilder } from "../../extensions/content-groups/core-client/ContentGroupRequestBuilder.js";
import { ChainKeyRequestBuilder } from "../../extensions/chain-keys/core-client/ChainKeyRequestBuilder.js";
import { OmissionRequestBuilder } from "../../extensions/content-key-seal-omission/core-client/OmissionRequestBuilder.js";
import {
  ChainKeyCache,
  type EvictionPolicy,
} from "../../extensions/chain-keys/core-client/ChainKeyCache.js";
import {
  openMapItems,
  type MapKeyClient,
} from "../../extensions/html-content-map/core-client/mapItems.js";
import type {
  ExtensionKeyFamilies,
  RouteProjection,
} from "../../core-client/requestBuilderContracts.js";

const groups = new ContentGroupRequestBuilder();
const chains = new ChainKeyRequestBuilder({ innerBuilder: groups });
const omission = new OmissionRequestBuilder({ innerBuilder: chains });
const families: ExtensionKeyFamilies = omission.keyFamilies({});
const projection: RouteProjection = groups.routeProjection;
projection.project({}, projection.identities({}));
// @ts-expect-error a key-family report uses boolean flags
const badFamilies: ExtensionKeyFamilies = { contentKeys: "yes", familyKeys: false };
// @ts-expect-error a projection supplies all four duties and its sealed member list
const badProjection: RouteProjection = { members: [], identities: () => [] };

const eviction: EvictionPolicy = (entry, { now }) => {
  const pool: "chain" = entry.pool;
  return pool === "chain" && entry.t.length === 0 && Number.isFinite(now.getTime());
};
new ChainKeyCache({ clock: { now: () => new Date() }, evictionPolicy: eviction });
eviction(
  // @ts-expect-error the eviction callback does not receive secret key material
  { pool: "chain", t: "261014T1200", kind: "chain-key", key: new Uint8Array(16) },
  { now: new Date() },
);

declare const mapClient: MapKeyClient;
openMapItems(mapClient, ["bodytext"]);
const unlock: MapKeyClient["unlock"] = async () => ({ status: 200 });
const skip: MapKeyClient["unlock"] = async () => ({ skipped: "no-eligible-route" });
// @ts-expect-error an observable status is numeric
const badUnlock: MapKeyClient["unlock"] = async () => ({ status: "200" });
void [families, badFamilies, badProjection, unlock, skip, badUnlock];
