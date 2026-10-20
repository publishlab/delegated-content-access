export type RegistryKey = {
  /**
   * - nonempty, for example "dca.content-handler"
   */
  interface: string;
  /**
   * - a positive safe integer
   */
  major: number;
  /**
   * - nonempty, for example "article"
   */
  name: string;
};
export type RegistryEntry<Provider extends object = object> = {
  provider: Provider | null;
  registration: object | null;
};
export type RegistryListener<Provider extends object = object> = (
  entry: RegistryEntry<Provider>,
  stop: () => void,
) => void;
export type ClientRegistry = {
  apiMajor: 1;
  /**
   *   Throws when the key is taken. The returned disposer is idempotent and only
   *   ever removes its own registration.
   */
  register: <Provider extends object>(key: RegistryKey, provider: Provider) => () => void;
  lookup: <Provider extends object>(key: RegistryKey) => Provider | null;
  observe: <Provider extends object>(
    key: RegistryKey,
    listener: RegistryListener<Provider>,
  ) => () => void;
  /**
   * - diagnostics only, never provider selection
   */
  keys: () => RegistryKey[];
};
/**
 * Finds a compatible registry on `host` or installs a new one. It keeps an
 * existing namespace and its unrelated members. It refuses a namespace that is
 * not an object and a registry without `apiMajor` 1 and the four methods. An
 * explicit `undefined` or `null` counts as an installation, and an invalid one.
 *
 * @param {object} [host]
 * @returns {ClientRegistry}
 */
export declare function installRegistry(host?: object): ClientRegistry;
