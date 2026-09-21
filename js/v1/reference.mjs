// This file is the reference's public testing surface: one import for a bridge or
// driver that runs this implementation from outside its own tree. A bridge in another
// repository imports this file and nothing deeper, so renaming or moving a module
// below it leaves that bridge working. Every name here comes from inside this tree,
// so the dependency runs one way, from a consumer into this file.
//
// Add to this surface only what a consumer needs. Additions are cheap; a rename or
// removal here breaks every bridge that imports that name, so keep a name fixed once
// a consumer outside this tree imports it.

export { seal, open } from "./core-shared--publisher-issuer/keySealing.js";
export { encrypt, decrypt, NONCE_BYTES, TAG_BYTES } from "./core-shared/aead.js";
export { base64urlEncode, base64urlDecode, utf8Encode, utf8Decode } from "./core-shared/codec.js";
export {
  bindValue,
  bindFields,
  RENDER_ID_BYTES,
  CONTENT_KIND,
  PERIOD_KIND,
} from "./core-shared--publisher-issuer/bind.js";
export { proofHash, verify } from "./core-shared--publisher-issuer/jwt.js";
export { formatT } from "./core-shared--publisher-issuer/periodKeys.js";
export { checkEnvelopes } from "./core-issuer/IssuerEngine.js";
export { DcaRequest } from "./core-shared--client-issuer/DcaRequest.js";
export { isAccessGroup, isContentName } from "./core-shared/names.js";
// The exact-period profiles and the lookup that returns one by name. A consumer
// proving a width reads that width from the profile rather than from the length of a
// value it read on the wire.
export { EXACT_PERIOD_PROFILE, exactPeriodProfile } from "./core-shared/exactPeriodProfiles.js";
export { AAD_DELIMITER } from "./core-shared--client-publisher/names.js";
export { MarkupDeliveryReader } from "./adapter-client/MarkupDeliveryReader.js";
export { PeriodKeyCache } from "./adapter-client/PeriodKeyCache.js";
export { DcaData } from "./core-client/DcaData.js";
export { DcaRequestBuilder } from "./core-client/DcaRequestBuilder.js";
export { ContentKeyResolver } from "./core-client/ContentKeyResolver.js";
export { ResponseAssociation } from "./core-client/ResponseAssociation.js";
export { openContent } from "./core-client/openContent.js";
export { ContentRepresentationOpener } from "./core-client/ContentRepresentationOpener.js";

// The portable issuer-endpoint seam and its static reference binding. The binding
// drives the wire endpoint: `unlock` takes a raw request document and returns the
// `{ status, body }` response. `unlock` is the binding's only member, so the issuer
// core stays behind it.
export {
  issuerEndpointContract,
  issuerEndpointRejectVectorContract,
} from "./test-contract/issuer-endpoint/support/issuer-endpoint-contract.js";
export { dcaTestBinding } from "./test-contract/issuer-endpoint/bindings/reference-issuer-endpoint-binding.js";

// The reference client, for a consumer that receives and opens sealed
// content.
export { Client } from "./test-lib/harnesses/client.js";
