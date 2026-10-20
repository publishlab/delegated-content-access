export type ContextSnapshot = {
  /**
   * - nonnegative safe integer, increasing per source
   */
  sequence: number;
  contextKnown: boolean;
  contextRevision: string | number | boolean | null;
};
export type ContextListener = (snapshot: ContextSnapshot, stop: () => void) => void;
export type ContextSourceProvider = {
  subscribe: (listener: ContextListener) => () => void;
};
export type ContextSourceController = {
  provider: ContextSourceProvider;
  /**
   *   Accepts a later sequence and returns true; ignores an older or equal one, or
   *   any publication after `end`, and returns false.
   */
  publish: (snapshot: ContextSnapshot) => boolean;
  /**
   *   Sends the next sequence as a final unknown snapshot and stops every subscriber.
   */
  end: () => void;
};
/**
 * @param {ContextSnapshot} initialSnapshot - the state before any change; it may be unknown
 * @returns {ContextSourceController}
 */
export declare function createContextSource(
  initialSnapshot: ContextSnapshot,
): ContextSourceController;
/**
 * Consumer admission: a frozen copy with exactly the three members. Any
 * nonnegative safe integer is an ordinary sequence here, the last one included.
 *
 * @param {unknown} snapshot
 * @returns {ContextSnapshot}
 */
export declare function admitSnapshot(snapshot: unknown): ContextSnapshot;
