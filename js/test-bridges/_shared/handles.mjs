// The driver side of object handles. A test target's adapter answers with a
// handle for an object of a class it claims; the driver hands the test one
// proxy per handle and session. The proxy has no prototype and no state of its
// own: each member the class description lists calls the test target with the
// handle as its receiver, and every other string member read throws. Nothing
// here knows a domain class; class descriptions arrive through discovery.

/** @typedef {import("./serializer.mjs").HandleTag} HandleTag */
/** @typedef {{ id: string, sourceMember: string, callShape: 'sync'|'async' }} ClassMember */
/** @typedef {{ id: string, sourceModule: string, sourceExport: string, construct?: { id: string }, members: readonly ClassMember[] }} ClassDescription */

/**
 * The table that issued each live proxy, over every session in this process.
 *
 * @type {WeakMap<object, HandleTable>}
 */
const owners = new WeakMap();

/**
 * One session's handles: from the adapter's discovery until the binding is
 * disposed. It implements the serializer's `HandleCodec`.
 */
export class HandleTable {
  /** @type {(id: string) => ClassDescription | undefined} */ #classOf;
  /** @type {(member: ClassMember, receiver: object, input: unknown[]) => unknown} */ #invoke;
  /** @type {Map<string, { proxy: object, tag: HandleTag }>} */ #byHandle = new Map();
  /** @type {WeakMap<object, HandleTag>} */ #tags = new WeakMap();
  #disposed = false;

  /**
   * @param {{ classOf: (id: string) => ClassDescription | undefined, invoke: (member: ClassMember, receiver: object, input: unknown[]) => unknown }} options
   *   `classOf` names a class a described module declared. `invoke` calls one
   *   member of the test target's object with `receiver` as the handle.
   */
  constructor({ classOf, invoke }) {
    this.#classOf = classOf;
    this.#invoke = invoke;
  }

  get disposed() {
    return this.#disposed;
  }

  /** Ends the session: every proxy it issued is refused from now on. */
  dispose() {
    this.#disposed = true;
  }

  /**
   * The tag of a proxy this session issued, or undefined for any value that
   * is no proxy. A proxy of another or of a disposed session is refused.
   *
   * @param {object} value @returns {HandleTag | undefined}
   */
  encode(value) {
    const owner = owners.get(value);
    if (owner === undefined) return undefined;
    owner.#assertLive();
    if (owner !== this) throw new TypeError("bridge handle belongs to another session");
    this.#assertLive();
    const tag = /** @type {HandleTag} */ (this.#tags.get(value));
    return { $type: "Handle", class: tag.class, handle: tag.handle };
  }

  /**
   * The one proxy for the object `tag` names in this session.
   *
   * @param {HandleTag} tag @returns {object}
   */
  decode(tag) {
    this.#assertLive();
    const known = this.#byHandle.get(tag.handle);
    if (known !== undefined) {
      if (known.tag.class !== tag.class)
        throw new TypeError(`bridge handle ${tag.handle} changed its class`);
      return known.proxy;
    }
    const description = this.#classOf(tag.class);
    if (description === undefined)
      throw new TypeError(
        `bridge handle names class ${tag.class}, which no described module declares`,
      );
    const stored = Object.freeze({ $type: "Handle", class: tag.class, handle: tag.handle });
    const proxy = this.#proxy(description);
    this.#byHandle.set(tag.handle, { proxy, tag: stored });
    this.#tags.set(proxy, stored);
    owners.set(proxy, this);
    return proxy;
  }

  #assertLive() {
    if (this.#disposed) throw new TypeError("bridge handle belongs to a disposed session");
  }

  /**
   * A proxy whose claimed members call the test target. It has no prototype,
   * so it borrows no reference method, and it refuses every write.
   *
   * @param {ClassDescription} description @returns {object}
   */
  #proxy(description) {
    const label = `${description.sourceModule} ${description.sourceExport}`;
    /** @type {Map<string, Function>} */
    const methods = new Map();
    const readOnly = () => {
      throw new TypeError(`bridge handles are read-only: ${label}`);
    };
    /** @type {object} */
    let proxy;
    for (const member of description.members) {
      const method = (/** @type {unknown[]} */ ...input) => {
        this.#assertLive();
        return this.#invoke(member, proxy, input);
      };
      methods.set(member.sourceMember, method);
    }
    const target = Object.freeze(Object.create(null));
    proxy = new Proxy(target, {
      get(_target, key) {
        // Symbols are how the runtime and inspection probe an object, and a
        // `then` read is how a promise asks whether a value is one. Neither
        // is a member call.
        if (typeof key === "symbol") return undefined;
        const method = methods.get(key);
        if (method !== undefined) return method;
        if (key === "then") return undefined;
        throw new TypeError(`${label}: the test target claims no member ${key}`);
      },
      has(_target, key) {
        return typeof key === "string" && methods.has(key);
      },
      set: readOnly,
      defineProperty: readOnly,
      deleteProperty: readOnly,
      setPrototypeOf: readOnly,
    });
    return proxy;
  }
}
