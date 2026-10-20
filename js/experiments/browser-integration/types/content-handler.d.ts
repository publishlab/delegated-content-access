export type ValueMode = "bytes" | "strictUTF8";
export type Commit = (effect: () => void) => boolean;
export type ContentInput = {
  contentName: string;
  /**
   * - the item's required `contentType`, as captured at connect
   */
  contentType: string;
  /**
   * - bytes, or text under `strictUTF8`
   */
  value: Uint8Array | string;
  commit: Commit;
};
export type CallbackOutcome = {
  status: "handled" | "refused" | "failed";
  reason?: string;
};
export type ContentCallback = (input: ContentInput) => CallbackOutcome | Promise<CallbackOutcome>;
export type ConnectionSetup = {
  /**
   * - the captured delivery object with own `contentData` records
   */
  delivery: object;
  /**
   * - synchronous check of the captured context and destination
   */
  isEligible: () => boolean;
  /**
   * - one callback per content name
   */
  targets: Record<string, ContentCallback>;
  /**
   * - per-name mode; a name left out gets bytes
   */
  values?: Record<string, ValueMode>;
};
export type ContentOutcome = {
  status: "handled" | "refused" | "failed" | "stale";
  reason?: string;
};
export type ContentConnection = {
  handleContent: (content: Record<string, Uint8Array>) => Promise<Record<string, ContentOutcome>>;
  dispose: () => void;
};
export type ContentHandler = {
  connect: (setup: ConnectionSetup) => ContentConnection;
};
/**
 * The provider. It holds no state; every connection captures its own.
 *
 * @param {Record<string, never>} [options] - no member is supported yet
 * @returns {ContentHandler}
 */
export declare function createContentHandler(options?: Record<string, never>): ContentHandler;
