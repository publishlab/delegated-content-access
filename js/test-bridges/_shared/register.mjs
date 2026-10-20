import { Worker } from "node:worker_threads";
import { registerHooks } from "node:module";
import { existsSync, realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isAbsolute, relative, resolve, sep } from "node:path";

import { DEFAULT_MAX_FRAME_BYTES, DEFAULT_TIMEOUT_MS, assertResponse } from "./protocol.mjs";
import {
  bridgeEnvironment,
  bridgeMode,
  bridgeModules,
  refuseObsoleteVariables,
} from "./environment.mjs";
import { TimingWriter } from "./timing.mjs";
import { TranscriptWriter } from "./transcript.mjs";
import {
  decodeValue,
  decodeValueAsync,
  encodeValue,
  encodeValueAsync,
  bridgeValueTypes,
} from "./serializer.mjs";
import {
  isDriverOwnedModule,
  isIdentifier,
  isSafeModulePath,
  validateDescription,
  validateModuleClasses,
  validateModuleMembers,
} from "./routing.mjs";
import { HandleTable } from "./handles.mjs";
import { convertAnswer, loadReferenceShapes, returnShape } from "./reference-shapes.mjs";
import { portableSelection } from "./run-support.mjs";

/** @typedef {{ id: string, adapter: string | undefined, adapterCwd: string, targetRoot: string | undefined, command: string, arguments: readonly string[] }} BridgeDefinition */
/** @typedef {{ id: string, sourceExport: string, callShape: 'sync'|'async'|'value' }} ModuleMember */
/** @typedef {{ id: string, sourceModule: string, sourceExport: string }} ErrorType */
/** @typedef {import("./handles.mjs").ClassDescription} ClassDescription */
/** @typedef {import("./handles.mjs").ClassMember} ClassMember */
/** @typedef {ClassMember & { classId: string }} MemberOperation */
/** @typedef {{ module: string, class: string }} ConstructorOptIn */
/** @typedef {{ valueTypes: readonly string[], moduleDiscovery: true }} CapabilitySnapshot */
/** @typedef {import("./run-support.mjs").InputMapping} InputMapping */
/** @typedef {{ module: string, export: string, argument: number }} IgnoredArgumentMapping */
/**
 * An input mapping with its class resolved: `type` is the class the driver's
 * tests construct, which the argument must be an instance of.
 *
 * @typedef {InputMapping & { type: Function }} BoundInputMapping
 */

/** @param {unknown} value @returns {value is { infrastructure: string }} */
function isInfrastructureFailure(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    "infrastructure" in value &&
    typeof value.infrastructure === "string"
  );
}

/**
 * States an infrastructure failure: its kind, the child's exit code or signal,
 * its message, and the tail of the adapter's stderr.
 *
 * @param {{ infrastructure: string, code?: unknown, signal?: unknown, message?: unknown, stderr?: unknown }} failure
 */
function infrastructureText(failure) {
  const exit = [
    typeof failure.code === "number" ? `exit code ${failure.code}` : undefined,
    typeof failure.signal === "string" ? `signal ${failure.signal}` : undefined,
  ].filter((part) => part !== undefined);
  let text = failure.infrastructure;
  if (exit.length !== 0) text += ` (${exit.join(", ")})`;
  if (typeof failure.message === "string" && failure.message !== "") text += `: ${failure.message}`;
  if (typeof failure.stderr === "string" && failure.stderr.trim() !== "")
    text += `\nadapter stderr (last 4 KiB):\n${failure.stderr.trimEnd()}`;
  return text;
}

/**
 * A `sync` call whose target entry returned a promise: the test gets a
 * promise with the same outcome, not an immediate value or throw.
 *
 * @param {unknown} response
 */
function isPromised(response) {
  return /** @type {any} */ (response)?.settled === "promise";
}

/** @param {unknown} value */
function isUncarried(value) {
  return (
    !isInfrastructureFailure(value) && /** @type {any} */ (value)?.result?.kind === "uncarried"
  );
}

/** @param {string} referenceRoot @param {string} sourceModule */
function referenceModulePath(referenceRoot, sourceModule) {
  if (!isSafeModulePath(sourceModule))
    throw new TypeError("bridge reference module names a safe relative JavaScript path");
  const root = realpathSync(resolve(referenceRoot));
  const candidate = realpathSync(resolve(root, sourceModule));
  const containment = relative(root, candidate);
  if (
    containment === "" ||
    containment === ".." ||
    containment.startsWith(".." + sep) ||
    isAbsolute(containment)
  )
    throw new TypeError("bridge reference module stays below the trusted reference root");
  return candidate;
}

/**
 * The own `name` property an instance of a reference error class gets from
 * its constructor, as `DcaError` sets one, read from one instance built
 * without arguments. Undefined when instances inherit their name or the
 * constructor needs arguments.
 *
 * @param {Function} constructor
 * @returns {PropertyDescriptor | undefined}
 */
function constructedName(constructor) {
  try {
    return Object.getOwnPropertyDescriptor(Reflect.construct(constructor, []), "name");
  } catch {
    return undefined;
  }
}

/** @param {string} sourceModule @param {string} sourceExport */
function errorId(sourceModule, sourceExport) {
  return `error-${Buffer.from(`${sourceModule}\0${sourceExport}`).toString("base64url")}`;
}

export class ProcessBinding {
  /** @type {BridgeDefinition} */ definition;
  /** @type {Worker | undefined} */ worker;
  /** @type {CapabilitySnapshot | undefined} */ capabilities;
  /** @type {unknown} */ description;
  /** @type {string[]} */ diagnostics;
  /** @type {number} */ externalCalls;
  /** @type {Map<string, ModuleMember>} */ operations;
  /** @type {Map<string, readonly ModuleMember[]>} */ moduleDescriptions;
  /** @type {Map<string, string>} */ operationModules;
  /** @type {import("./reference-shapes.mjs").ReferenceShapes | undefined} */ referenceShapes;
  /** @type {readonly ErrorType[]} */ errorDescriptors;
  /** @type {Map<string, { constructor: Function, prototype: object, name?: PropertyDescriptor }>} */ errorTypes;
  /** @type {Record<string, { external: number, reference: number, uncarried?: number }>} */ routes;
  /** @type {readonly BoundInputMapping[]} */ inputs;
  /** @type {readonly IgnoredArgumentMapping[]} */ ignoredArguments;
  /** @type {Map<string, readonly ClassDescription[]>} */ moduleClasses;
  /** @type {Map<string, ClassDescription>} */ classes;
  /** @type {Map<string, MemberOperation>} */ memberOperations;
  /** @type {Map<string, string>} each claimed constructor's operation ID and its class ID */ constructOperations;
  /** @type {HandleTable} */ handles;
  /** @type {readonly string[] | undefined} */ modules;
  /** @type {Set<string>} */ unroutedModules;

  /**
   * @param {BridgeDefinition} definition
   * @param {{ timeout?: number, maximum?: number, transcriptPath?: string, timingPath?: string, timing?: boolean, debug?: boolean, mode?: 'overlay'|'strict', modules?: readonly string[], entry?: string, referenceShapes?: import("./reference-shapes.mjs").ReferenceShapes, inputs?: readonly BoundInputMapping[], ignoredArguments?: readonly IgnoredArgumentMapping[] }} [options]
   *   `modules` is the named module set of a strict run;
   *   `referenceShapes` replaces the committed reference-shapes.json;
   *   `inputs` lists the arguments that cross as the data of a class instance.
   *   `ignoredArguments` lists source-declared unused arguments that cross as `undefined`.
   */
  constructor(definition, options = {}) {
    this.definition = definition;
    this.mode = options.mode;
    this.modules = options.modules;
    this.unroutedModules = new Set();
    this.entry = options.entry;
    // Routes record what was called, not what discovery made callable.
    this.routes = {};
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
    this.maximum = options.maximum ?? DEFAULT_MAX_FRAME_BYTES;
    this.transcript = new TranscriptWriter(options.transcriptPath);
    this.timing = new TimingWriter(options.timingPath, options.timing === true);
    this.referenceFallbacks = 0;
    this.uncarriedResults = 0;
    this.debug = options.debug === true;
    this.diagnostics = [];
    this.externalCalls = 0;
    this.operations = new Map();
    this.moduleDescriptions = new Map();
    this.operationModules = new Map();
    this.referenceShapes = options.referenceShapes;
    this.inputs = options.inputs ?? Object.freeze([]);
    this.ignoredArguments = validateIgnoredArguments(options.ignoredArguments);
    for (const ignored of this.ignoredArguments) {
      if (
        this.inputs.some(
          (input) =>
            input.module === ignored.module &&
            input.export === ignored.export &&
            input.argument === ignored.argument,
        )
      ) {
        throw new TypeError(
          "an argument cannot have both an input mapping and an ignored-argument mapping",
        );
      }
    }
    this.errorDescriptors = Object.freeze([]);
    this.errorTypes = new Map();
    this.moduleClasses = new Map();
    this.classes = new Map();
    this.memberOperations = new Map();
    this.constructOperations = new Map();
    // One session: the adapter process this binding starts, until dispose.
    this.handles = new HandleTable({
      classOf: (id) => this.classes.get(id),
      invoke: (member, receiver, input) => {
        return member.callShape === "async"
          ? this.callAsync(member.id, input, receiver)
          : this.call(member.id, input, receiver);
      },
    });
    /** @type {string | undefined} */ this.broken = undefined;
    /** @type {number | undefined} The adapter child's pid until the worker sees it reaped. */
    this.childPid = undefined;
    this.workerClosed = false;
    // Node does not stop a child when the parent exits. A test process that
    // ends without dispose must not leave its adapter running.
    this.killChildAtExit = () => {
      if (this.childPid !== undefined) {
        try {
          process.kill(this.childPid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
    };
  }

  async start() {
    refuseObsoleteVariables();
    this.report("starting bridge worker");
    const worker = new Worker(new URL("./bridge-worker.mjs", import.meta.url), {
      workerData: { ...this.definition, maximum: this.maximum },
      // A preload is inherited by workers unless explicitly removed. Letting
      // this preload install another bridge worker recursively prevents the
      // channel from ever becoming ready.
      execArgv: [],
    });
    this.worker = worker;
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error("bridge worker did not start")),
        this.timeout,
      );
      worker.once("message", (message) => {
        clearTimeout(timeout);
        if (message.type === "ready") {
          this.childPid = message.pid;
          process.once("exit", this.killChildAtExit);
          resolve(undefined);
        } else reject(new Error("bridge worker gave no ready signal"));
      });
      worker.on("message", (message) => {
        if (message.type === "diagnostic") {
          this.diagnostics.push(message.text);
          this.report(`adapter diagnostic: ${message.text.trim()}`);
        }
        if (message.type === "exited") this.childPid = undefined;
      });
      worker.once("error", reject);
      worker.once("exit", () => {
        this.workerClosed = true;
      });
    });
    const description = this.request({ version: 1, type: "describe" });
    if (isInfrastructureFailure(description))
      throw new Error(`bridge describe failed: ${infrastructureText(description)}`);
    const response = assertResponse(description);
    if (response.result.kind !== "observation")
      throw new Error("bridge describe did not observe capabilities");
    const described = decodeValue(response.result.value);
    if (!described || typeof described !== "object")
      throw new Error("bridge describe has no description object");
    this.description = described;
    const validated = validateDescription(described);
    this.capabilities = validated.capabilities;
    this.errorDescriptors = validated.errorTypes;
    this.report("capabilities module discovery");
    if (this.transcript.path)
      this.transcript.write("capabilities", {
        description: this.description,
        ...(this.entry === undefined ? {} : { entry: this.entry }),
      });
    // Tests should retain normal Node lifecycle behavior. The worker remains
    // available while calls are pending, but it is not an implicit keepalive.
    worker.unref();
    return this;
  }

  /** @param {string} referenceRoot */
  async preloadErrorTypes(referenceRoot) {
    const namespaces = new Map();
    for (const descriptor of this.errorDescriptors) {
      const modulePath = referenceModulePath(referenceRoot, descriptor.sourceModule);
      let namespace = namespaces.get(modulePath);
      if (!namespace) {
        namespace = await import(pathToFileURL(modulePath).href);
        namespaces.set(modulePath, namespace);
      }
      const constructor = namespace[descriptor.sourceExport];
      if (
        typeof constructor !== "function" ||
        !constructor.prototype ||
        !Object.prototype.isPrototypeOf.call(Error.prototype, constructor.prototype)
      )
        throw new TypeError("bridge error type export has an Error prototype");
      this.registerErrorType(descriptor.id, constructor);
    }
  }

  /**
   * Registers a reference error class for refusals that name `id`. The class's
   * constructor runs once here, never when an error is rebuilt.
   *
   * @param {string} id @param {Function} constructor
   */
  registerErrorType(id, constructor) {
    const name = constructedName(constructor);
    this.errorTypes.set(
      id,
      Object.freeze({
        constructor,
        prototype: constructor.prototype,
        ...(name === undefined ? {} : { name }),
      }),
    );
  }

  /** @param {{ code: string, message?: string, errorType?: string }} result */
  refusalError(result) {
    if (result.errorType?.startsWith("native-dom:")) {
      const name = result.errorType.slice("native-dom:".length);
      if (typeof DOMException === "function") return new DOMException(result.message, name);
    }
    if (result.errorType?.startsWith("native:")) {
      const name = result.errorType.slice("native:".length);
      /** @type {Record<string, Function>} */
      const constructors = {
        Error,
        TypeError,
        RangeError,
        ReferenceError,
        SyntaxError,
        EvalError,
        URIError,
        AggregateError,
      };
      const constructor = /** @type {ErrorConstructor | undefined} */ (constructors[name]);
      if (constructor) {
        const error = new constructor(result.message);
        /** @type {Error & { code?: unknown }} */ (error).code = result.code;
        return error;
      }
    }
    if (result.errorType === undefined) {
      const error = new Error(result.message ?? result.code);
      /** @type {Error & { code?: unknown }} */ (error).code = result.code;
      return error;
    }
    const errorType = this.errorTypes.get(result.errorType);
    if (!errorType) throw new Error("bridge refusal names an unknown error type");
    const error = new Error(result.message);
    Object.setPrototypeOf(error, errorType.prototype);
    if (errorType.name) Object.defineProperty(error, "name", errorType.name);
    Object.defineProperties(error, {
      code: { configurable: true, enumerable: true, value: result.code, writable: true },
      message: {
        configurable: true,
        enumerable: false,
        value: result.message,
        writable: true,
      },
    });
    return error;
  }

  /**
   * Calls a discovered export, or with `receiver` a member of the object that
   * proxy stands for. `promised` keeps the promise shape of a reference export
   * declared `async` that the test target answers synchronously: the answer
   * resolves the returned promise and the target's refusal rejects it. A
   * bridge failure still throws at once, so it cannot pass for a rejection.
   *
   * @param {string} operation @param {unknown[]} input @param {object} [receiver]
   * @param {boolean} [promised]
   */
  call(operation, input, receiver, promised = false) {
    this.assertClaimed(operation, receiver);
    if (this.broken) throw new Error(`bridge infrastructure failure: ${this.broken}`);
    const mapped = this.mapInputs(operation, input);
    const encoded = encodeValue(mapped.input, this.handles);
    const target = this.receiverTag(receiver);
    this.assertValueTypes(encoded);
    const started = this.timing.now();
    this.report(`dispatch ${operation}`);
    const response = this.request(callFrame(operation, encoded, mapped.instances, target));
    this.timing.call(this.timing.now() - started);
    if (isUncarried(response)) return this.uncarried(operation, encoded, response);
    this.externalCalls += 1;
    this.route(operation).external += 1;
    if (this.transcript.path)
      this.transcript.write("call", {
        operation,
        input: encoded,
        ...(mapped.instances ? { instances: mapped.instances } : {}),
        ...(target ? { receiver: target } : {}),
        response,
      });
    if (isInfrastructureFailure(response))
      throw new Error(`bridge infrastructure failure: ${infrastructureText(response)}`);
    const result = assertResponse(response).result;
    if (isPromised(response) && result.kind === "observation") {
      this.report(`observed ${operation}`);
      return decodeValueAsync(result.value, this.handles).then((value) =>
        this.answer(operation, result, value),
      );
    }
    if (isPromised(response) && result.kind === "refusal")
      return Promise.reject(this.refusalError(result));
    if (result.kind === "observation") {
      this.report(`observed ${operation}`);
      const value = this.answer(operation, result, decodeValue(result.value, this.handles));
      return promised ? Promise.resolve(value) : value;
    }
    if (result.kind === "refusal") {
      const refusal = this.refusalError(result);
      if (promised) return Promise.reject(refusal);
      throw refusal;
    }
    if (result.kind === "unsupported")
      throw new Error(`bridge operation is unsupported: ${operation}`);
    throw new Error("bridge response has an unknown result");
  }

  /**
   * Calls a discovered asynchronous export, or with `receiver` an
   * asynchronous member of the object that proxy stands for.
   *
   * @param {string} operation @param {unknown[]} input @param {object} [receiver]
   */
  async callAsync(operation, input, receiver) {
    const mapped = this.mapInputs(operation, input);
    let encoded;
    try {
      encoded = await encodeValueAsync(mapped.input, this.handles);
    } catch (error) {
      if (isHandleRefusal(error)) throw error;
      throw new TypeError("bridge input cannot be serialized", { cause: error });
    }
    this.assertClaimed(operation, receiver);
    if (this.broken) throw new Error(`bridge infrastructure failure: ${this.broken}`);
    const target = this.receiverTag(receiver);
    this.assertValueTypes(encoded);
    const started = this.timing.now();
    this.report(`dispatch ${operation}`);
    const response = this.request(callFrame(operation, encoded, mapped.instances, target));
    this.timing.call(this.timing.now() - started);
    return this.observeAsync(operation, encoded, mapped.instances, target, response);
  }

  /**
   * Reads the response of an asynchronous call.
   *
   * @param {string} operation @param {unknown} encoded
   * @param {{ argument: number, sourceModule: string, sourceExport: string }[] | undefined} instances
   * @param {import("./serializer.mjs").HandleTag | undefined} target @param {unknown} response
   */
  async observeAsync(operation, encoded, instances, target, response) {
    if (isUncarried(response)) return this.uncarried(operation, encoded, response);
    this.externalCalls += 1;
    this.route(operation).external += 1;
    if (this.transcript.path)
      this.transcript.write("call", {
        operation,
        input: encoded,
        ...(instances ? { instances } : {}),
        ...(target ? { receiver: target } : {}),
        response,
      });
    if (isInfrastructureFailure(response))
      throw new Error(`bridge infrastructure failure: ${infrastructureText(response)}`);
    const result = assertResponse(response).result;
    if (result.kind === "observation") {
      this.report(`observed ${operation}`);
      return this.answer(operation, result, await decodeValueAsync(result.value, this.handles));
    }
    if (result.kind === "refusal") {
      throw this.refusalError(result);
    }
    if (result.kind === "unsupported")
      throw new Error(`bridge operation is unsupported: ${operation}`);
    throw new Error("bridge response has an unknown result");
  }

  /**
   * The test target ran the call and answered, but the bridge cannot carry
   * the answer back: its result is no bridge value, or the call changed its
   * arguments. That is a limit of the bridge, not a failure of the target.
   * The call fails in both modes. The target already ran it, so a rerun on
   * the reference would repeat its effects and pass on the reference's
   * answer. The attempt counts in `uncarriedResults`, never as an external
   * call, an observation or a fallback.
   *
   * @param {string} operation @param {unknown} encoded @param {unknown} response
   */
  uncarried(operation, encoded, response) {
    const { message } = assertResponse(response).result;
    this.uncarriedResults += 1;
    const route = this.route(operation);
    route.uncarried = (route.uncarried ?? 0) + 1;
    if (this.transcript.path)
      this.transcript.write("uncarried", { operation, input: encoded, response });
    this.report(`uncarried ${operation}`);
    const error = new Error(
      `bridge cannot carry the result of ${this.operationName(operation)}: ${message}`,
    );
    if (isPromised(response)) return Promise.reject(error);
    throw error;
  }

  /**
   * Refuses an operation discovery did not claim, and a call whose receiver
   * does not fit it: a class member needs a receiver, an export or a
   * constructor takes none.
   *
   * @param {string} operation @param {object | undefined} receiver
   */
  assertClaimed(operation, receiver) {
    const member = this.memberOperations.get(operation);
    const export_ = this.operations.has(operation);
    const constructor = this.constructOperations.has(operation);
    const claimed = export_ || constructor;
    if (member === undefined && !claimed)
      throw new Error(`bridge operation is not claimed: ${operation}`);
    if (member !== undefined && receiver === undefined)
      throw new Error(`bridge member ${this.operationName(operation)} needs a receiver`);
    if (member === undefined && receiver !== undefined)
      throw new Error(`bridge export ${this.operationName(operation)} takes no receiver`);
  }

  /**
   * The handle of `receiver`, a proxy this session issued, or undefined for a
   * call without one. A proxy of another or a disposed session is refused.
   *
   * @param {object | undefined} receiver
   */
  receiverTag(receiver) {
    if (receiver === undefined) return undefined;
    const tag = this.handles.encode(receiver);
    if (tag === undefined) throw new TypeError("bridge call receiver is no bridge handle");
    return tag;
  }

  /**
   * Reads a test target's answer by the reference export's return shape,
   * which reference-shapes.mjs describes: only a value with one reading
   * changes. A type the test target declared and the reference does not admit
   * is refused.
   *
   * @param {string} operation @param {{ declared?: import("./reference-shapes.mjs").Declared }} result
   * @param {unknown} value
   */
  answer(operation, result, value) {
    // A class member has no export entry, so its answer is read as it came.
    const sourceModule = this.operationModules.get(operation);
    const member = this.operations.get(operation);
    this.referenceShapes ??= loadReferenceShapes();
    const shape =
      sourceModule === undefined || member === undefined
        ? undefined
        : returnShape(this.referenceShapes, sourceModule, member.sourceExport);
    try {
      return convertAnswer(shape, value, result.declared);
    } catch (error) {
      throw new Error(
        `bridge refuses the result of ${this.operationName(operation)}: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error },
      );
    }
  }

  /** @param {string} operation */
  operationName(operation) {
    const constructed = this.classes.get(this.constructOperations.get(operation) ?? "");
    if (constructed !== undefined)
      return `new ${constructed.sourceModule} ${constructed.sourceExport}`;
    for (const [sourceModule, members] of this.moduleDescriptions)
      for (const member of members)
        if (member.id === operation) return `${sourceModule} ${member.sourceExport}`;
    const member = this.memberOperations.get(operation);
    const owner = member === undefined ? undefined : this.classes.get(member.classId);
    if (member !== undefined && owner !== undefined)
      return `${owner.sourceModule} ${owner.sourceExport}#${member.sourceMember}`;
    return operation;
  }

  /**
   * Whether the bridge can carry `input` to `operation`, after its input
   * mappings apply.
   *
   * @param {unknown[]} input @param {string} [operation]
   */
  canCarry(input, operation) {
    const mapped = operation === undefined ? { input } : this.mapInputs(operation, input);
    try {
      this.assertValueTypes(encodeValue(mapped.input, this.handles));
      return true;
    } catch {
      return false;
    }
  }

  /** @param {unknown[]} input @param {string} [operation] */
  async canCarryAsync(input, operation) {
    const mapped = operation === undefined ? { input } : this.mapInputs(operation, input);
    try {
      this.assertValueTypes(await encodeValueAsync(mapped.input, this.handles));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Applies the input mappings listed for `operation`'s export. A listed
   * argument that holds an instance of its class crosses as what the class's
   * data method returns, marked in the frame by the class coordinate. Every
   * other value keeps its prior path: a plain record at a listed position
   * crosses as a plain record, unmarked, and meets the test target's own
   * refusal; an instance of the same class at a position no mapping lists is
   * still no bridge value.
   *
   * @param {string} operation @param {unknown[]} input
   * @returns {{ input: unknown[], instances?: { argument: number, sourceModule: string, sourceExport: string }[] }}
   */
  mapInputs(operation, input) {
    const sourceModule = this.operationModules.get(operation);
    const sourceExport = this.operations.get(operation)?.sourceExport;
    const ignored = this.ignoredArguments.filter(
      (mapping) => mapping.module === sourceModule && mapping.export === sourceExport,
    );
    const projected = ignored.length === 0 ? input : Array.isArray(input) ? [...input] : input;
    for (const mapping of ignored) {
      if (!Array.isArray(projected) || mapping.argument >= projected.length) {
        throw new TypeError("an ignored-argument mapping names an existing call argument");
      }
      projected[mapping.argument] = undefined;
    }
    const listed = this.inputs.filter(
      (mapping) => mapping.module === sourceModule && mapping.export === sourceExport,
    );
    if (listed.length === 0 || !Array.isArray(projected)) return { input: projected };
    const mapped = [...projected];
    const instances = [];
    for (const mapping of listed) {
      const value = input[mapping.argument];
      if (!(value instanceof mapping.type)) continue;
      mapped[mapping.argument] = /** @type {any} */ (value)[mapping.data]();
      instances.push({
        argument: mapping.argument,
        sourceModule: mapping.class.module,
        sourceExport: mapping.class.export,
      });
    }
    return instances.length === 0
      ? { input: ignored.length === 0 ? input : mapped }
      : { input: mapped, instances };
  }

  /** @param {any} value */
  assertValueTypes(value) {
    const supported = this.capabilities?.valueTypes;
    if (!supported) throw new Error("bridge did not describe runtime value types");
    const unsupported = [...bridgeValueTypes(value)].filter((type) => !supported.includes(type));
    if (unsupported.length)
      throw new TypeError(`bridge does not support runtime value types: ${unsupported.join(", ")}`);
  }

  /** @param {string} sourceModule @returns {readonly ModuleMember[]} */
  describeModule(sourceModule) {
    if (!isSafeModulePath(sourceModule))
      throw new TypeError("bridge source module is a safe relative JavaScript path");
    const cached = this.moduleDescriptions.get(sourceModule);
    if (cached) return cached;
    const response = this.request({ version: 1, type: "describeModule", sourceModule });
    if (isInfrastructureFailure(response))
      throw new Error(`bridge module description failed: ${infrastructureText(response)}`);
    const result = assertResponse(response).result;
    if (result.kind === "unsupported" || result.kind === "refusal") {
      this.report(
        `module ${sourceModule} unavailable${result.kind === "refusal" ? `: ${result.message ?? result.code}` : ""}`,
      );
      /** @type {readonly ModuleMember[]} */ const members = Object.freeze([]);
      this.moduleDescriptions.set(sourceModule, members);
      this.moduleClasses.set(sourceModule, Object.freeze([]));
      return members;
    }
    if (result.kind !== "observation")
      throw new Error("bridge module description did not observe members");
    const described = decodeValue(result.value);
    const members = validateModuleMembers(described);
    const declared = validateModuleClasses(described, members);
    const operationIds = [
      ...members.map((member) => member.id),
      ...declared.flatMap((entry) => entry.members.map((member) => member.id)),
      ...declared.flatMap((entry) => (entry.construct === undefined ? [] : [entry.construct.id])),
    ];
    const taken = operationIds.filter(
      (id) =>
        this.operations.has(id) ||
        this.memberOperations.has(id) ||
        this.constructOperations.has(id),
    );
    if (taken.length) throw new TypeError(`bridge member IDs already claimed: ${taken.join(", ")}`);
    const takenClasses = declared.filter((entry) => this.classes.has(entry.id));
    if (takenClasses.length)
      throw new TypeError(
        `bridge class IDs already claimed: ${takenClasses.map((entry) => entry.id).join(", ")}`,
      );
    this.report(
      `module ${sourceModule}: ${members.map((member) => member.sourceExport).join(", ")}`,
    );
    for (const member of members) {
      this.operations.set(member.id, member);
      this.operationModules.set(member.id, sourceModule);
    }
    const classes = Object.freeze(
      declared.map((entry) => Object.freeze({ ...entry, sourceModule })),
    );
    for (const entry of classes) {
      this.classes.set(entry.id, entry);
      for (const member of entry.members)
        this.memberOperations.set(member.id, Object.freeze({ ...member, classId: entry.id }));
      if (entry.construct !== undefined) this.constructOperations.set(entry.construct.id, entry.id);
    }
    this.moduleDescriptions.set(sourceModule, members);
    this.moduleClasses.set(sourceModule, classes);
    if (this.transcript.path)
      this.transcript.write("module", {
        sourceModule,
        members,
        ...(declared.length === 0 ? {} : { classes: declared }),
      });
    return members;
  }

  /**
   * Builds an object of the class `sourceExport` of `sourceModule` in the
   * test target, from `input`, and answers its handle proxy. The class must be
   * one a described module declared with a constructor; any other is refused
   * before dispatch, in every mode, and nothing runs the reference
   * constructor. After dispatch the answer must be a handle of that class, or
   * the call fails.
   *
   * @param {string} sourceModule @param {string} sourceExport @param {unknown[]} input
   * @returns {object}
   */
  construct(sourceModule, sourceExport, input) {
    const described = this.moduleClasses
      .get(sourceModule)
      ?.find((entry) => entry.sourceExport === sourceExport);
    const constructor = described?.construct;
    if (described === undefined || constructor === undefined)
      throw new Error(
        `strict bridge run: new ${sourceModule} ${sourceExport} is not claimed by the test target`,
      );
    const answer = this.call(constructor.id, input);
    const object = answer !== null && typeof answer === "object" ? answer : undefined;
    const tag = object === undefined ? undefined : this.handles.encode(object);
    if (object === undefined || tag?.class !== described.id)
      throw new Error(
        `bridge refuses the result of ${this.operationName(constructor.id)}: the test target answered no object of the class`,
      );
    return object;
  }

  /** @param {string} operation @param {unknown} input @param {(...values: unknown[]) => unknown} fallback */
  referenceFallback(operation, input, fallback) {
    if (!Array.isArray(input)) throw new TypeError("reference fallback input is an argument list");
    this.referenceFallbacks += 1;
    this.route(operation).reference += 1;
    if (this.transcript.path) {
      // The input may be the very value that made this call fall back.
      let encoded;
      try {
        encoded = encodeValue(input, this.handles);
      } catch (error) {
        encoded = { uncarried: error instanceof Error ? error.message : String(error) };
      }
      this.transcript.write("route", { operation, route: "reference", input: encoded });
    }
    this.report(`reference fallback ${operation}`);
    return fallback(...input);
  }

  /** @param {string} operation */
  route(operation) {
    this.routes[operation] ??= { external: 0, reference: 0 };
    return this.routes[operation];
  }

  /** @param {string} message */
  report(message) {
    if (this.debug) process.stderr.write(`dca bridge ${this.definition.id}: ${message}\n`);
  }

  /**
   * Posts `message` to the worker and waits for its answer: its JSON text,
   * `{ timedOut: true }`, or `{ size: -1 }` when the answer did not fit the
   * payload.
   *
   * @param {Record<string, unknown>} message @returns {{ timedOut: true } | { size: -1 } | { text: string }}
   */
  exchange(message) {
    if (!this.worker) throw new Error("bridge worker is not started");
    const control = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
    const payload = new SharedArrayBuffer(this.maximum);
    const state = new Int32Array(control);
    this.worker.postMessage({ ...message, control, payload });
    if (Atomics.wait(state, 0, 0, this.timeout) === "timed-out") return { timedOut: true };
    const size = Atomics.load(state, 1);
    if (size < 0) return { size: -1 };
    return { text: new TextDecoder().decode(new Uint8Array(payload, 0, size)) };
  }

  /**
   * The export names of the reference module at `moduleUrl`, each with its
   * kind: `function`, `class` or `value`. The worker imports the module
   * without the bridge hooks and reads its namespace.
   *
   * @param {string} moduleUrl @returns {[string, "function" | "class" | "value"][]}
   */
  referenceExports(moduleUrl) {
    const answer = this.exchange({ type: "exports", url: moduleUrl });
    const failure =
      "timedOut" in answer
        ? "timeout"
        : "size" in answer
          ? "the export list exceeds the payload"
          : undefined;
    const result = failure === undefined && "text" in answer ? JSON.parse(answer.text) : undefined;
    if (failure !== undefined || typeof result?.error === "string")
      throw new Error(`bridge cannot list the exports of ${moduleUrl}: ${failure ?? result.error}`);
    return result.exports;
  }

  /**
   * A strict run's stand-in for a function export the test target does not
   * claim. It fails the call: running the reference function would pass the
   * test on reference code that no evidence counts.
   *
   * @param {string} sourceModule @param {string} sourceExport
   * @returns {never}
   */
  unclaimed(sourceModule, sourceExport) {
    throw new Error(
      `strict bridge run: ${sourceModule}#${sourceExport} is not claimed by the test target`,
    );
  }

  /** @param {Record<string, unknown>} request @returns {unknown} */
  request(request) {
    if (!this.worker) throw new Error("bridge worker is not started");
    if (this.broken) return { infrastructure: "broken", message: this.broken };
    const answer = this.exchange({ type: "call", request });
    if ("timedOut" in answer) {
      // The adapter child may still be working on the stuck call, so every
      // later call would time out too. Kill it and refuse further calls.
      this.breakBinding({ infrastructure: "timeout" }, "a timeout");
      if (this.transcript.path)
        this.transcript.write("infrastructure", { phase: "call", failure: "timeout" });
      return { infrastructure: "timeout" };
    }
    /** @type {unknown} */
    let result;
    if ("size" in answer)
      result = {
        infrastructure: "response_too_large",
        message: `bridge result exceeds the ${this.maximum}-byte payload`,
      };
    else
      try {
        result = JSON.parse(answer.text);
      } catch {
        result = { infrastructure: "malformed_response" };
      }
    if (isInfrastructureFailure(result)) this.breakBinding(result);
    return result;
  }

  /**
   * After any infrastructure failure the channel can no longer be trusted:
   * stop the adapter child and fail every later call without dispatch.
   *
   * @param {{ infrastructure: string }} failure @param {string} [cause]
   */
  breakBinding(failure, cause) {
    // The first failure carries the adapter's stderr; later ones name the cause only.
    this.broken = `binding is broken after ${cause ?? infrastructureText({ ...failure, stderr: undefined })}`;
    this.worker?.postMessage({ type: "kill" });
  }

  /** An overlay run that sent nothing across proves nothing about a test target. */
  get vacuous() {
    return this.mode === "overlay" && this.externalCalls === 0;
  }

  /**
   * The preload never sees test outcomes. The final record therefore states
   * the lifecycle and what crossed; the verdict belongs to the Node run.
   */
  async dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.report("disposing");
    this.handles.dispose();
    if (this.transcript.path)
      this.transcript.write("final", {
        lifecycle: "disposed",
        ...(this.mode === undefined ? {} : { mode: this.mode }),
        ...(this.entry === undefined ? {} : { entry: this.entry }),
        ...(this.modules === undefined
          ? {}
          : { modules: this.modules, unroutedModules: [...this.unroutedModules].sort() }),
        routes: this.routes,
        externalCalls: this.externalCalls,
        referenceFallbacks: this.referenceFallbacks,
        uncarriedResults: this.uncarriedResults,
        ...(this.vacuous ? { evidence: "vacuous" } : {}),
      });
    this.timing.finish({ lifecycle: "disposed" });
    const worker = this.worker;
    if (!worker) return;
    try {
      const acknowledgement = this.request({ version: 1, type: "dispose" });
      if (isInfrastructureFailure(acknowledgement))
        this.transcript.write("infrastructure", { phase: "dispose", failure: acknowledgement });
      else assertResponse(acknowledgement);
    } finally {
      // Whether or not the adapter acknowledged, the worker stops the child
      // and waits until it is reaped, so dispose leaves no process behind.
      if (!this.workerClosed)
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, this.timeout);
          const done = () => {
            clearTimeout(timer);
            resolve(undefined);
          };
          worker.on("message", (message) => {
            if (message.type === "closed") done();
          });
          worker.once("exit", done);
          worker.postMessage({ type: "close" });
        });
      process.removeListener("exit", this.killChildAtExit);
      this.killChildAtExit();
      await worker.terminate();
    }
  }
}

/** @param {readonly IgnoredArgumentMapping[] | undefined} mappings */
function validateIgnoredArguments(mappings) {
  if (mappings === undefined) return Object.freeze([]);
  if (!Array.isArray(mappings)) throw new TypeError("ignored arguments are a list");
  const listed = new Set();
  return Object.freeze(
    mappings.map((mapping) => {
      if (
        mapping === null ||
        typeof mapping !== "object" ||
        Array.isArray(mapping) ||
        Object.keys(mapping).sort().join("\0") !== ["argument", "export", "module"].join("\0") ||
        !isSafeModulePath(mapping.module) ||
        isDriverOwnedModule(mapping.module) ||
        !isIdentifier(mapping.export) ||
        !Number.isSafeInteger(mapping.argument) ||
        mapping.argument < 0
      ) {
        throw new TypeError(
          "ignored arguments name a source module, export and non-negative argument index",
        );
      }
      const key = `${mapping.module}\0${mapping.export}\0${mapping.argument}`;
      if (listed.has(key)) throw new TypeError("ignored arguments list each source argument once");
      listed.add(key);
      return Object.freeze({
        module: mapping.module,
        export: mapping.export,
        argument: mapping.argument,
      });
    }),
  );
}

/**
 * A call frame, with `instances` only when an input mapping marked an argument
 * and `receiver` only for a class member.
 *
 * @param {string} operation @param {unknown} input
 * @param {{ argument: number, sourceModule: string, sourceExport: string }[] | undefined} instances
 * @param {import("./serializer.mjs").HandleTag | undefined} receiver
 */
function callFrame(operation, input, instances, receiver) {
  return {
    version: 1,
    type: "call",
    protocol: "dca-test-bridge/v1",
    operation,
    input,
    ...(instances ? { instances } : {}),
    ...(receiver ? { receiver } : {}),
  };
}

/**
 * Whether `error` is the handle table refusing a proxy of another or a
 * disposed session, which a caller must see as it is.
 *
 * @param {unknown} error
 */
function isHandleRefusal(error) {
  return error instanceof TypeError && /^bridge handle belongs to /.test(error.message);
}

/**
 * Under `node --test` process isolation each test file runs in its own child
 * process, with the file as its first argument. Transcripts record it so a
 * runner can attribute calls to a test file.
 *
 * @param {string} referenceRoot
 */
function testEntry(referenceRoot) {
  const file = process.argv[1];
  if (!process.env.NODE_TEST_CONTEXT?.startsWith("child") || file === undefined) return undefined;
  const path = relative(referenceRoot, file);
  return isSafeModulePath(path) ? path : file;
}

/**
 * The query that names a module's reference fallback instance. The load hook
 * leaves such a module unproxied, and the resolve hook keeps its imports in
 * the same fallback graph.
 */
const FALLBACK_QUERY = "?dca-bridge-reference-fallback";

/** @param {string} moduleUrl */
function referenceFallbackUrl(moduleUrl) {
  return `${moduleUrl}${FALLBACK_QUERY}`;
}

/**
 * @param {string} moduleUrl @param {string} sourceModule @param {readonly ModuleMember[]} members
 * @param {'overlay'|'strict'} mode
 * @param {readonly [string, string][]} unclaimedFunctions in strict mode, the reference's function exports no member claims
 * @param {readonly string[]} [constructed] the class exports whose `new` the run routes to the test target
 */
function proxyModule(moduleUrl, sourceModule, members, mode, unclaimedFunctions, constructed = []) {
  const fallbackUrl = referenceFallbackUrl(moduleUrl);
  // A routed class is a function, so `new` builds the test target's object
  // and returns its handle proxy. It has none of the reference class's
  // prototype or statics, and it refuses a call without `new` and a subclass.
  const constructors = constructed
    .map((sourceExport, index) => {
      const name = `__dcaConstruct${index}`;
      const label = JSON.stringify(`${sourceModule} ${sourceExport}`);
      return `function ${name}(...input) {
  if (new.target === undefined) throw new TypeError(${label} + " is a class; construct it with new");
  if (new.target !== ${name}) throw new TypeError(${label} + ": a routed class cannot be subclassed");
  return globalThis.__dcaBridgeProcessBinding.construct(${JSON.stringify(sourceModule)}, ${JSON.stringify(sourceExport)}, input);
}
export { ${name} as ${JSON.stringify(sourceExport)} };`;
    })
    .join("\n");
  // A local export takes precedence over the same name from `export *`.
  const standIns = unclaimedFunctions
    .map(
      ([sourceExport], index) =>
        `const __dcaUnclaimed${index} = () => globalThis.__dcaBridgeProcessBinding.unclaimed(${JSON.stringify(sourceModule)}, ${JSON.stringify(sourceExport)});\nexport { __dcaUnclaimed${index} as ${JSON.stringify(sourceExport)} };`,
    )
    .join("\n");
  // A synchronous target entry for a reference export declared `async` still
  // answers the test with a promise, so `promised` is true for it.
  const promised = (/** @type {string} */ sourceExport) =>
    `Object.prototype.toString.call(referenceFallback[${JSON.stringify(sourceExport)}]) === "[object AsyncFunction]"`;
  const replacements = members
    .filter((member) => member.callShape === "sync" || member.callShape === "async")
    .map(({ id, sourceExport, callShape }) =>
      callShape === "async"
        ? mode === "strict"
          ? `export const ${sourceExport} = typeof referenceFallback[${JSON.stringify(sourceExport)}] === "function" ? async (...input) => globalThis.__dcaBridgeProcessBinding.callAsync(${JSON.stringify(id)}, input) : referenceFallback[${JSON.stringify(sourceExport)}];`
          : `export const ${sourceExport} = typeof referenceFallback[${JSON.stringify(sourceExport)}] === "function" ? async (...input) => { const reference = async (...values) => referenceFallback[${JSON.stringify(sourceExport)}](...values); return await globalThis.__dcaBridgeProcessBinding.canCarryAsync(input, ${JSON.stringify(id)}) ? globalThis.__dcaBridgeProcessBinding.callAsync(${JSON.stringify(id)}, input) : globalThis.__dcaBridgeProcessBinding.referenceFallback(${JSON.stringify(id)}, input, reference); } : referenceFallback[${JSON.stringify(sourceExport)}];`
        : mode === "strict"
          ? `export const ${sourceExport} = typeof referenceFallback[${JSON.stringify(sourceExport)}] === "function" ? (...input) => globalThis.__dcaBridgeProcessBinding.call(${JSON.stringify(id)}, input, undefined, ${promised(sourceExport)}) : referenceFallback[${JSON.stringify(sourceExport)}];`
          : `export const ${sourceExport} = typeof referenceFallback[${JSON.stringify(sourceExport)}] === "function" ? (...input) => { const reference = (...values) => referenceFallback[${JSON.stringify(sourceExport)}](...values); return globalThis.__dcaBridgeProcessBinding.canCarry(input, ${JSON.stringify(id)}) ? globalThis.__dcaBridgeProcessBinding.call(${JSON.stringify(id)}, input, undefined, ${promised(sourceExport)}) : globalThis.__dcaBridgeProcessBinding.referenceFallback(${JSON.stringify(id)}, input, reference); } : referenceFallback[${JSON.stringify(sourceExport)}];`,
    )
    .join("\n");
  return `import * as referenceFallback from ${JSON.stringify(fallbackUrl)};\nexport * from ${JSON.stringify(fallbackUrl)};\n${replacements}\n${standIns}\n${constructors}\n`;
}

/**
 * The reference fallback instance of a module, with a trailer that registers
 * its error classes with the driver. Every mapped reference error therefore
 * has the prototype the test's own imports see.
 *
 * @param {string} moduleUrl @param {string} sourceModule @param {string} source
 */
function fallbackModule(moduleUrl, sourceModule, source) {
  return `${source}\nimport * as __dcaBridgeSelf from ${JSON.stringify(moduleUrl)};\nif (globalThis.__dcaBridgeRegisterErrors) globalThis.__dcaBridgeRegisterErrors(${JSON.stringify(sourceModule)}, __dcaBridgeSelf);\n`;
}

/**
 * Registers direct function substitutions discovered from modules Node loads.
 *
 * `inputs` lists the arguments that cross as the data of a class instance.
 * Each class is imported from the reference once the hooks are in place, so
 * the driver checks instances against the class the tests construct.
 *
 * `modules`, the named module set, limits a strict run to those reference
 * modules: every other implementation module loads as its reference fallback
 * instance, so its calls never cross.
 *
 * `constructors` opts classes of a strict run into constructor routing: in
 * the module that exports it, each listed class becomes a stand-in whose `new`
 * builds the test target's object. Every other class stays the reference's.
 *
 * @param {BridgeDefinition} definition
 * @param {{ mode?: 'overlay'|'strict', modules?: readonly string[], constructors?: readonly ConstructorOptIn[], transcriptPath?: string, timingPath?: string, timing?: boolean, debug?: boolean, inputs?: readonly InputMapping[], ignoredArguments?: readonly IgnoredArgumentMapping[] }} [options]
 */
export async function registerBridge(definition, options = {}) {
  const mode = bridgeMode(options.mode);
  const referenceRoot = fileURLToPath(new URL("../../", import.meta.url));
  const modules = options.modules;
  if (modules !== undefined) {
    if (mode !== "strict")
      throw new TypeError(
        "DCA_BRIDGE_MODULES names the modules of a strict run; set DCA_BRIDGE_MODE=strict",
      );
    for (const module of modules) {
      const present = isSafeModulePath(module) && existsSync(resolve(referenceRoot, module));
      if (!present)
        throw new TypeError(`DCA_BRIDGE_MODULES names ${module}, which is no reference module`);
    }
  }
  const ignoredArguments = validateIgnoredArguments(options.ignoredArguments);
  for (const ignored of ignoredArguments) {
    const present = existsSync(resolve(referenceRoot, ignored.module));
    if (!present)
      throw new TypeError(`ignored argument names ${ignored.module}, which is no reference module`);
    if (
      (options.inputs ?? []).some(
        (input) =>
          input.module === ignored.module &&
          input.export === ignored.export &&
          input.argument === ignored.argument,
      )
    ) {
      throw new TypeError(
        "an argument cannot have both an input mapping and an ignored-argument mapping",
      );
    }
  }
  const constructors = options.constructors ?? [];
  if (constructors.length !== 0 && mode !== "strict")
    throw new TypeError(
      "constructor opt-ins route classes of a strict run; set DCA_BRIDGE_MODE=strict",
    );
  for (const constructor of constructors) {
    const present =
      isSafeModulePath(constructor.module) &&
      !isDriverOwnedModule(constructor.module) &&
      existsSync(resolve(referenceRoot, constructor.module));
    if (!present)
      throw new TypeError(
        `constructor opt-in names ${constructor.module}, which is no reference implementation module`,
      );
    const outsideSet = modules !== undefined && !modules.includes(constructor.module);
    if (outsideSet)
      throw new TypeError(
        `constructor opt-in names ${constructor.module}, which the named module set leaves unrouted`,
      );
  }
  const { inputs = [], constructors: _optIns, ...bindingOptions } = options;
  const binding = await new ProcessBinding(definition, {
    ...bindingOptions,
    mode,
    entry: testEntry(referenceRoot),
  }).start();
  /** @type {typeof globalThis & { __dcaBridgeProcessBinding?: ProcessBinding; __dcaBridgeRegisterErrors?: (sourceModule: string, namespace: Record<string, unknown>) => void }} */ (
    globalThis
  ).__dcaBridgeProcessBinding = binding;
  /** @param {string} sourceModule @param {Record<string, unknown>} namespace */
  const bridgeGlobal =
    /** @type {typeof globalThis & { __dcaBridgeRegisterErrors?: (sourceModule: string, namespace: Record<string, unknown>) => void }} */ (
      globalThis
    );
  bridgeGlobal.__dcaBridgeRegisterErrors = (sourceModule, namespace) => {
    for (const [sourceExport, constructor] of Object.entries(namespace)) {
      if (
        typeof constructor === "function" &&
        constructor.prototype &&
        Object.prototype.isPrototypeOf.call(Error.prototype, constructor.prototype)
      ) {
        binding.registerErrorType(errorId(sourceModule, sourceExport), constructor);
      }
    }
  };
  /**
   * The reference module path of an implementation module URL that may cross,
   * or undefined for any other URL.
   *
   * @param {URL} parsed
   */
  const implementationModule = (parsed) => {
    if (parsed.protocol !== "file:") return undefined;
    const sourceModule = relative(referenceRoot, fileURLToPath(parsed));
    if (!isSafeModulePath(sourceModule) || isDriverOwnedModule(sourceModule)) return undefined;
    return sourceModule;
  };
  registerHooks({
    // A call that falls back runs entirely on the reference: every
    // implementation module a fallback instance imports is a fallback too,
    // so its internal calls never reach the proxies.
    resolve(specifier, context, nextResolve) {
      const resolved = nextResolve(specifier, context);
      if (context.parentURL === undefined || !context.parentURL.endsWith(FALLBACK_QUERY))
        return resolved;
      const parsed = new URL(resolved.url);
      if (parsed.search || implementationModule(parsed) === undefined) return resolved;
      return { ...resolved, url: referenceFallbackUrl(resolved.url) };
    },
    load(url, context, nextLoad) {
      const parsed = new URL(url);
      if (parsed.search === FALLBACK_QUERY) {
        const plain = new URL(url);
        plain.search = "";
        const sourceModule = implementationModule(plain);
        const loaded = nextLoad(url, context);
        if (sourceModule === undefined || loaded.format !== "module" || loaded.source === undefined)
          return loaded;
        // A module only the fallback graph loads is described too, so the
        // test target registers its error classes.
        binding.describeModule(sourceModule);
        const source =
          typeof loaded.source === "string"
            ? loaded.source
            : new TextDecoder().decode(loaded.source);
        return { ...loaded, shortCircuit: true, source: fallbackModule(url, sourceModule, source) };
      }
      const sourceModule = parsed.search ? undefined : implementationModule(parsed);
      if (sourceModule === undefined) return nextLoad(url, context);
      // A module outside the named set is its reference fallback instance, like
      // a module with nothing to claim, and none of its calls cross.
      const routed = modules === undefined || modules.includes(sourceModule);
      if (!routed) {
        binding.unroutedModules.add(sourceModule);
        return {
          format: "module",
          shortCircuit: true,
          source: `export * from ${JSON.stringify(referenceFallbackUrl(url))};\n`,
        };
      }
      binding.report(`discover module ${sourceModule}`);
      const members = binding.describeModule(sourceModule);
      // Strict mode gives each function export the test target does not claim
      // a stand-in that fails the call. `export *` skips `default`, so the
      // proxy never exports one. Classes and other values stay the reference's.
      const claimed = new Set(
        members
          .filter((member) => member.callShape === "sync" || member.callShape === "async")
          .map((member) => member.sourceExport),
      );
      const referenceExports = mode === "strict" ? binding.referenceExports(url) : [];
      const unclaimedFunctions = referenceExports.filter(
        ([sourceExport, kind]) =>
          kind === "function" && sourceExport !== "default" && !claimed.has(sourceExport),
      );
      const constructed = constructors
        .filter((constructor) => constructor.module === sourceModule)
        .map((constructor) => constructor.class);
      for (const sourceExport of constructed) {
        const isClass = referenceExports.some(
          ([name, kind]) => name === sourceExport && kind === "class",
        );
        if (!isClass)
          throw new TypeError(
            `constructor opt-in names ${sourceModule} ${sourceExport}, which the reference module does not export as a class`,
          );
      }
      const nothingToRoute =
        members.length === 0 && unclaimedFunctions.length === 0 && constructed.length === 0;
      return {
        format: "module",
        shortCircuit: true,
        // A module with nothing to claim is its fallback instance, so the test
        // and the fallback graph share one copy of every class it exports.
        source: nothingToRoute
          ? `export * from ${JSON.stringify(referenceFallbackUrl(url))};\n`
          : proxyModule(url, sourceModule, members, mode, unclaimedFunctions, constructed),
      };
    },
  });
  // Preload through the registered hooks. Importing a reference error module
  // first would cache its unproxied copy for tests that import it later.
  await binding.preloadErrorTypes(referenceRoot);
  binding.inputs = await bindInputs(referenceRoot, inputs);
  return {
    mode,
    routes: binding.routes,
    binding,
    async dispose() {
      const emptyStrictRun = mode === "strict" && binding.externalCalls === 0;
      await binding.dispose();
      if (emptyStrictRun) {
        process.exitCode = 1;
        throw new Error("strict bridge run made no external calls");
      }
    },
  };
}

/**
 * Resolves each mapping's class from the reference fallback instance of its
 * module, the instance a test's own import of that class shares.
 *
 * @param {string} referenceRoot @param {readonly InputMapping[]} inputs
 * @returns {Promise<readonly BoundInputMapping[]>}
 */
async function bindInputs(referenceRoot, inputs) {
  const bound = [];
  for (const mapping of inputs) {
    const path = referenceModulePath(referenceRoot, mapping.class.module);
    if (isDriverOwnedModule(mapping.class.module))
      throw new TypeError("bridge input mapping names an implementation class module");
    const namespace = await import(referenceFallbackUrl(pathToFileURL(path).href));
    const type = namespace[mapping.class.export];
    if (typeof type !== "function" || typeof type.prototype?.[mapping.data] !== "function")
      throw new TypeError(
        `bridge input mapping: ${mapping.class.module} ${mapping.class.export} is no class with a ${mapping.data} method`,
      );
    bound.push(Object.freeze({ ...mapping, type }));
  }
  return Object.freeze(bound);
}

/**
 * Starts a bridge module's definition with the settings from the process
 * environment: `DCA_BRIDGE_MODE`, `DCA_BRIDGE_MODULES`, `DCA_LOG_DIR`, `DCA_TIMING`
 * and `DCA_DEBUG`.
 * `DCA_TEST_SELECTION` names the selection whose input mappings and
 * constructor opt-ins apply; a run without it maps no input and routes no
 * constructor. The adapter is disposed when the Node process drains.
 *
 * @param {BridgeDefinition} definition
 * @param {{ ignoredArguments?: readonly IgnoredArgumentMapping[] }} [options]
 */
export async function startBridge(definition, options = {}) {
  const environment = bridgeEnvironment({ bridgeId: definition.id });
  /** @param {string} message */
  const debug = (message) => {
    if (environment.debug) process.stderr.write(`dca bridge ${definition.id}: ${message}\n`);
  };
  const mode = bridgeMode(process.env.DCA_BRIDGE_MODE);
  const modules = bridgeModules(process.env.DCA_BRIDGE_MODULES);
  const selectionName = process.env.DCA_TEST_SELECTION;
  const selection =
    selectionName === undefined
      ? undefined
      : portableSelection({
          v1Root: fileURLToPath(new URL("../../", import.meta.url)),
          name: selectionName,
        });
  const inputs = selection?.inputs ?? [];
  const constructors = selection?.constructors ?? [];
  debug("starting adapter");
  const active = await registerBridge(definition, {
    mode,
    modules,
    inputs,
    constructors,
    ignoredArguments: options.ignoredArguments,
    transcriptPath: "transcriptPath" in environment ? environment.transcriptPath : undefined,
    timingPath: "timingPath" in environment ? environment.timingPath : undefined,
    timing: environment.timing,
    debug: environment.debug,
  });
  debug(`ready; mode ${active.mode}`);
  process.once("beforeExit", () => {
    debug("disposing adapter");
    return active.dispose();
  });
  return active;
}
