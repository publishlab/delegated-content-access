<?php

declare(strict_types=1);

namespace Dca\TestBridge;

use Dca\TestBridge\Value\BytesValue;
use Dca\TestBridge\Value\ListValue;

final class TargetMap
{
    /** Each setting names an attribute class; its value defaults to the class the bridge ships. */
    private const ATTRIBUTE_SETTINGS = [
        'module' => ['DCA_PHP_MODULE_ATTRIBUTE', 'Dca\\Porting\\SourceModule'],
        'export' => ['DCA_PHP_EXPORT_ATTRIBUTE', 'Dca\\Porting\\SourceExport'],
        'returnType' => ['DCA_PHP_RETURN_TYPE_ATTRIBUTE', 'Dca\\Porting\\ReturnType'],
    ];

    /** @var array<string, array{callable: \Closure, parameters: list<\ReflectionParameter>, sourceModule: string, sourceExport: string, returnType: string|array<mixed>|null}> */
    private array $operations;
    /** @var array<string, list<array{id: string, sourceExport: string, callShape: string}>> */
    private array $members;
    /** @var array<string, array{id: string, class: class-string<\Throwable>}> */
    private array $errorClasses;
    /** @var list<array{id: string, sourceModule: string, sourceExport: string}> */
    private array $errorTypes;
    /** @var array<string, array{class: class-string, method: string, parameters: list<\ReflectionParameter>, returnType: string|array<mixed>|null}> */
    private array $classMembers = [];
    /** @var array<string, list<array{id: string, sourceExport: string, construct?: array{id: string}, members: list<array{id: string, sourceMember: string, callShape: string}>}>> */
    private array $classes = [];
    /** @var array<string, array{class: class-string, parameters: list<\ReflectionParameter>}> each claimed constructor, by its operation ID */
    private array $constructors = [];
    /** @var array<class-string, string> */
    private array $classIds = [];
    private string $bytesClass;
    private string $undefinedClass;

    /** @param array<string, array{callable: \Closure, parameters: list<\ReflectionParameter>, sourceModule: string, sourceExport: string, returnType: string|array<mixed>|null}> $operations */
    /** @param array<string, list<array{id: string, sourceExport: string, callShape: string}>> $members */
    /** @param array<string, array{id: string, class: class-string<\Throwable>}> $errorClasses */
    /** @param list<array{id: string, sourceModule: string, sourceExport: string}> $errorTypes */
    private function __construct(array $operations, array $members, array $errorClasses, array $errorTypes, string $bytesClass, string $undefinedClass)
    {
        $this->operations = $operations;
        $this->members = $members;
        $this->errorClasses = $errorClasses;
        $this->errorTypes = $errorTypes;
        $this->bytesClass = $bytesClass;
        $this->undefinedClass = $undefinedClass;
    }

    /**
     * Discovers the test target named by the environment. A module attribute's
     * path must name a file below `$referenceRoot`, the JavaScript reference.
     */
    public static function fromEnvironment(string $referenceRoot): self
    {
        $attributes = self::attributeNames();
        $bytesClass = self::configuredClass('DCA_PHP_BYTES_CLASS', 'Dca\\Porting\\Bytes');
        $undefinedClass = self::configuredClass('DCA_PHP_UNDEFINED_CLASS', 'Dca\\Porting\\Undefined');
        $resolvedReference = realpath($referenceRoot);
        if (!is_string($resolvedReference) || !is_dir($resolvedReference)) {
            throw new \RuntimeException('JavaScript reference root is a readable directory');
        }
        $root = getenv('DCA_TARGET_ROOT');
        if (!is_string($root) || $root === '' || !is_dir($root)) {
            throw new \RuntimeException('test target root is a readable directory');
        }
        $resolvedRoot = realpath($root);
        if (!is_string($resolvedRoot)) {
            throw new \RuntimeException('test target root is a readable directory');
        }
        $namespace = getenv('DCA_TARGET_NAMESPACE');
        if ($namespace === false) {
            $namespace = '';
        }
        if (!is_string($namespace)) {
            throw new \TypeError('test target namespace is a string');
        }
        $namespace = trim($namespace, '\\');
        if ($namespace !== '' && !preg_match('/^[A-Za-z_][A-Za-z0-9_]*(?:\\\\[A-Za-z_][A-Za-z0-9_]*)*$/', $namespace)) {
            throw new \TypeError('test target namespace has PHP identifier segments');
        }
        $files = self::targetFiles($resolvedRoot);
        // An autoload file replaces the one-prefix autoloader, so exactly one
        // loader serves the test target and discovery itself requires no file.
        $autoload = getenv('DCA_TARGET_AUTOLOAD');
        if ($autoload !== false) {
            self::requireAutoload($autoload);
            $prefix = null;
        } else {
            if ($namespace === '') {
                $namespace = self::inferredNamespace($resolvedRoot, $files);
            }
            self::registerTargetAutoloader($resolvedRoot, $namespace);
            $prefix = $namespace;
        }
        $discovered = [];
        $discoveredErrors = [];
        $discoveredClasses = [];
        foreach (self::candidateClasses($resolvedRoot, $files, $prefix) as $class) {
            if (!class_exists($class)) {
                continue;
            }
            $reflection = new \ReflectionClass($class);
            $module = self::sourceModule($reflection, $attributes['module'], $resolvedReference);
            if ($module === null) {
                continue;
            }
            if (is_subclass_of($class, \Throwable::class)) {
                $export = self::sourceExport($reflection, $attributes['export']);
                if ($export === null) {
                    throw new \TypeError('test target throwable class has one export marker');
                }
                $key = $module . '#' . $export;
                if (isset($discoveredErrors[$key])) {
                    throw new \TypeError("test target error types duplicate module export $key");
                }
                $discoveredErrors[$key] = ['class' => $class, 'sourceModule' => $module, 'sourceExport' => $export];
            }
            foreach ($reflection->getMethods(\ReflectionMethod::IS_PUBLIC | \ReflectionMethod::IS_STATIC) as $method) {
                if (!$method->isPublic() || !$method->isStatic() || $method->getDeclaringClass()->getName() !== $class || !self::supportsSignature($method, $bytesClass)) {
                    continue;
                }
                $export = self::exportName($method, $attributes['export']);
                $key = $module . '#' . $export;
                if (isset($discovered[$key])) {
                    throw new \TypeError("test target exports duplicate module export $key");
                }
                $discovered[$key] = [
                    'callable' => \Closure::fromCallable([$class, $method->getName()]),
                    'parameters' => $method->getParameters(),
                    'sourceModule' => $module,
                    'sourceExport' => $export,
                    'returnType' => self::returnValueType($method, $attributes['returnType']),
                ];
            }
            if (!is_subclass_of($class, \Throwable::class)) {
                $export = self::sourceExport($reflection, $attributes['export']) ?? $reflection->getShortName();
                $key = $module . '#' . $export;
                if (isset($discoveredClasses[$key])) {
                    throw new \TypeError("test target classes duplicate module export $key");
                }
                $discoveredClasses[$key] = [
                    'class' => $class,
                    'sourceModule' => $module,
                    'sourceExport' => $export,
                    'members' => self::instanceMembers($reflection, $attributes, $bytesClass),
                    'constructor' => self::constructorParameters($reflection, $bytesClass),
                ];
            }
            foreach ($reflection->getReflectionConstants(\ReflectionClassConstant::IS_PUBLIC) as $constant) {
                if (!preg_match('/^[A-Za-z_$][A-Za-z0-9_$]*$/', $constant->getName())) {
                    continue;
                }
                $key = $module . '#' . $constant->getName();
                if (isset($discovered[$key])) {
                    throw new \TypeError("test target exports duplicate module export $key");
                }
                $discovered[$key] = [
                    'callable' => null,
                    'parameters' => [],
                    'sourceModule' => $module,
                    'sourceExport' => $constant->getName(),
                    'returnType' => null,
                ];
            }
        }
        ksort($discovered, SORT_STRING);
        $operations = [];
        $members = [];
        foreach (array_values($discovered) as $index => $operation) {
            $id = 'op-' . ($index + 1);
            $callShape = $operation['callable'] instanceof \Closure ? 'sync' : 'value';
            $members[$operation['sourceModule']][] = ['id' => $id, 'sourceExport' => $operation['sourceExport'], 'callShape' => $callShape];
            if ($callShape === 'sync') {
                $operations[$id] = $operation;
            }
        }
        ksort($discoveredErrors, SORT_STRING);
        $errorClasses = [];
        $errorTypes = [];
        foreach ($discoveredErrors as $error) {
            $id = 'error-' . substr(hash('sha256', $error['sourceModule'] . "\0" . $error['sourceExport']), 0, 24);
            if (isset($errorClasses[$id])) {
                throw new \TypeError('test target error type IDs collide');
            }
            $errorClasses[$id] = ['id' => $id, 'class' => $error['class']];
            $errorTypes[] = [
                'id' => $id,
                'sourceModule' => $error['sourceModule'],
                'sourceExport' => $error['sourceExport'],
            ];
        }
        $map = new self($operations, $members, $errorClasses, $errorTypes, $bytesClass, $undefinedClass);
        // Member operation IDs continue after the export IDs, so adding a
        // class leaves every export's ID as it was.
        ksort($discoveredClasses, SORT_STRING);
        $next = count($discovered);
        foreach (array_values($discoveredClasses) as $index => $described) {
            $classId = 'class-' . ($index + 1);
            $map->classIds[$described['class']] = $classId;
            $classMembers = [];
            foreach ($described['members'] as $member) {
                $next++;
                $id = 'op-' . $next;
                $classMembers[] = ['id' => $id, 'sourceMember' => $member['sourceMember'], 'callShape' => 'sync'];
                $map->classMembers[$id] = [
                    'class' => $described['class'],
                    'method' => $member['method'],
                    'parameters' => $member['parameters'],
                    'returnType' => $member['returnType'],
                ];
            }
            // Constructor IDs have their own prefix and numbering, so a
            // constructor leaves every export and member ID as it was.
            $construct = [];
            if ($described['constructor'] !== null) {
                $constructId = 'new-' . ($index + 1);
                $map->constructors[$constructId] = ['class' => $described['class'], 'parameters' => $described['constructor']];
                $construct = ['construct' => ['id' => $constructId]];
            }
            $map->classes[$described['sourceModule']][] = [
                'id' => $classId,
                'sourceExport' => $described['sourceExport'],
            ] + $construct + [
                'members' => $classMembers,
            ];
        }
        return $map;
    }

    /**
     * The parameters of a class's constructor, or null when the class cannot
     * be constructed from bridge values: it is abstract, its constructor is not
     * public, or a parameter has a type discovery does not support. A class
     * without a constructor takes no parameters.
     *
     * @return list<\ReflectionParameter>|null
     */
    private static function constructorParameters(\ReflectionClass $reflection, string $bytesClass): ?array
    {
        if (!$reflection->isInstantiable()) {
            return null;
        }
        $constructor = $reflection->getConstructor();
        if ($constructor === null) {
            return [];
        }
        if (!self::supportsSignature($constructor, $bytesClass)) {
            return null;
        }
        return $constructor->getParameters();
    }

    /**
     * The public instance methods a claimed class declares itself, each under
     * its own name or the name its export attribute gives, sorted by that name.
     *
     * @param array{module: string, export: string, returnType: string} $attributes
     * @return list<array{sourceMember: string, method: string, parameters: list<\ReflectionParameter>, returnType: string|array<mixed>|null}>
     */
    private static function instanceMembers(\ReflectionClass $reflection, array $attributes, string $bytesClass): array
    {
        $members = [];
        foreach ($reflection->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
            $declared = $method->getDeclaringClass()->getName() === $reflection->getName();
            $instance = !$method->isStatic() && !$method->isConstructor() && !$method->isDestructor();
            $magic = str_starts_with($method->getName(), '__');
            if (!$declared || !$instance || $magic || !self::supportsSignature($method, $bytesClass)) {
                continue;
            }
            $name = self::exportName($method, $attributes['export']);
            if (isset($members[$name])) {
                throw new \TypeError("test target class {$reflection->getName()} claims member $name twice");
            }
            $members[$name] = [
                'sourceMember' => $name,
                'method' => $method->getName(),
                'parameters' => $method->getParameters(),
                'returnType' => self::returnValueType($method, $attributes['returnType']),
            ];
        }
        ksort($members, SORT_STRING);
        return array_values($members);
    }

    /** @return list<array{id: string, sourceExport: string, callShape: string}> */
    public function describeModule(string $sourceModule): array
    {
        self::assertModulePath($sourceModule);
        return $this->members[$sourceModule] ?? [];
    }

    /**
     * The classes a module's test target claims, each with the instance
     * members it claims and, when it can be constructed, its constructor.
     *
     * @return list<array{id: string, sourceExport: string, construct?: array{id: string}, members: list<array{id: string, sourceMember: string, callShape: string}>}>
     */
    public function describeClasses(string $sourceModule): array
    {
        self::assertModulePath($sourceModule);
        return $this->classes[$sourceModule] ?? [];
    }

    /** @return array<class-string, string> each claimed PHP class and its class ID */
    public function handleClasses(): array
    {
        return $this->classIds;
    }

    public function invoke(string $operation, array $input): mixed
    {
        if (isset($this->classMembers[$operation])) {
            throw new HandleRefusal('a member call needs a receiver handle');
        }
        if (isset($this->constructors[$operation])) {
            $constructor = $this->constructors[$operation];
            $arguments = $this->materializeArguments($input, $constructor['parameters']);
            return new ($constructor['class'])(...$arguments);
        }
        if (!isset($this->operations[$operation])) {
            throw new \OutOfBoundsException('bridge operation is unsupported');
        }
        $entry = $this->operations[$operation];
        $arguments = $this->materializeArguments($input, $entry['parameters']);
        return $this->shaped($entry['returnType'], ($entry['callable'])(...$arguments));
    }

    /** Runs one claimed instance member on `$receiver`, the object a handle named. */
    public function invokeMember(string $operation, object $receiver, array $input): mixed
    {
        if (isset($this->operations[$operation])) {
            throw new HandleRefusal('an export call takes no receiver');
        }
        if (isset($this->constructors[$operation])) {
            throw new HandleRefusal('a constructor call takes no receiver');
        }
        if (!isset($this->classMembers[$operation])) {
            throw new \OutOfBoundsException('bridge operation is unsupported');
        }
        $entry = $this->classMembers[$operation];
        if (get_class($receiver) !== $entry['class']) {
            throw new HandleRefusal("the receiver is no object of the member's class");
        }
        $arguments = $this->materializeArguments($input, $entry['parameters']);
        return $this->shaped($entry['returnType'], $receiver->{$entry['method']}(...$arguments));
    }

    /**
     * @param list<mixed> $input
     * @param list<\ReflectionParameter> $parameters
     * @return list<mixed>
     */
    private function materializeArguments(array $input, array $parameters): array
    {
        foreach ($input as $index => $value) {
            $parameter = $parameters[$index] ?? null;
            if ($parameter === null && $parameters !== []) {
                $last = $parameters[count($parameters) - 1];
                $parameter = $last->isVariadic() ? $last : null;
            }
            $input[$index] = $this->materializeInput($value, $parameter?->getType());
        }
        return $input;
    }

    /** The class used for explicitly ambiguous byte inputs and returned bytes. */
    public function bytesClass(): string
    {
        return $this->bytesClass;
    }

    private function materializeInput(mixed $value, ?\ReflectionType $type = null): mixed
    {
        if ($value instanceof BytesValue) {
            if ($this->usesBytesClass($type)) {
                return new ($this->bytesClass)($value->bytes);
            }
            return $value->bytes;
        }
        if ($value instanceof \stdClass) {
            foreach (get_object_vars($value) as $name => $member) {
                $value->{$name} = $this->materializeInput($member, $type);
            }
        } elseif (is_array($value)) {
            foreach ($value as $index => $member) {
                $value[$index] = $this->materializeInput($member, $type);
            }
        }
        return $value;
    }

    private function usesBytesClass(?\ReflectionType $type): bool
    {
        if ($type instanceof \ReflectionNamedType) {
            return $type->getName() === 'mixed' || ltrim($type->getName(), '\\') === $this->bytesClass;
        }
        if ($type instanceof \ReflectionUnionType) {
            foreach ($type->getTypes() as $member) {
                if ($member->getName() === 'string') {
                    return false;
                }
                if (ltrim($member->getName(), '\\') === $this->bytesClass) {
                    return true;
                }
            }
        }
        return false;
    }

    /** The class a port returns for `undefined`, from `DCA_PHP_UNDEFINED_CLASS`. */
    public function undefinedClass(): string
    {
        return $this->undefinedClass;
    }

    /** @return list<array{id: string, sourceModule: string, sourceExport: string}> */
    public function errorTypes(): array
    {
        return $this->errorTypes;
    }

    /** @return array{errorType: string, code: string, message: string}|null */
    public function classify(\Throwable $error): ?array
    {
        $selected = null;
        foreach ($this->errorClasses as $candidate) {
            if (!$error instanceof $candidate['class']) {
                continue;
            }
            if ($selected === null || is_a($candidate['class'], $selected['class'], true)) {
                $selected = $candidate;
            }
        }
        if ($selected === null) {
            return null;
        }
        $code = self::stableErrorCode($error);
        if ($code === null) {
            return null;
        }
        return ['errorType' => $selected['id'], 'code' => $code, 'message' => $error->getMessage()];
    }

    /** @return list<string> PHP file paths below the root, relative and without `.php`, sorted */
    private static function targetFiles(string $root): array
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
        );
        $paths = [];
        foreach ($iterator as $entry) {
            if (!$entry->isFile() || $entry->isLink() || $entry->getExtension() !== 'php') {
                continue;
            }
            $relative = substr($entry->getPathname(), strlen($root) + 1, -4);
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*(?:\/[A-Za-z_][A-Za-z0-9_]*)*$/', $relative)) {
                $paths[] = $relative;
            }
        }
        sort($paths, SORT_STRING);
        return $paths;
    }

    /**
     * Names the class each file declares: its declared namespace and its base
     * name. Beside the one-prefix autoloader for `$prefix`, a file declaring a
     * namespace under that prefix must sit where the autoloader looks for it.
     *
     * @param list<string> $files
     * @return list<string>
     */
    private static function candidateClasses(string $root, array $files, ?string $prefix): array
    {
        $classes = [];
        foreach ($files as $relative) {
            $declared = self::fileNamespace($root . DIRECTORY_SEPARATOR . $relative . '.php');
            $class = ($declared === '' ? '' : $declared . '\\') . basename($relative);
            if ($prefix !== null && $prefix !== ''
                && ($declared === $prefix || str_starts_with($declared, $prefix . '\\'))
                && $class !== $prefix . '\\' . str_replace('/', '\\', $relative)) {
                throw new \TypeError('test target namespace matches its directory path');
            }
            $classes[$class] = true;
        }
        return array_keys($classes);
    }

    private static function fileNamespace(string $path): string
    {
        $source = file_get_contents($path);
        if ($source === false) {
            throw new \RuntimeException('test target file is readable');
        }
        if (preg_match('/^\\s*namespace\\s+([A-Za-z_][A-Za-z0-9_]*(?:\\\\[A-Za-z_][A-Za-z0-9_]*)*)\\s*;/m', $source, $matches) !== 1) {
            return '';
        }
        return $matches[1];
    }

    /**
     * The namespace prefix of the first file that declares one, with the
     * file's directory segments removed from its end.
     *
     * @param list<string> $files
     */
    private static function inferredNamespace(string $root, array $files): string
    {
        foreach ($files as $relative) {
            $declared = self::fileNamespace($root . DIRECTORY_SEPARATOR . $relative . '.php');
            if ($declared === '') {
                continue;
            }
            $directories = explode('/', dirname($relative));
            if ($directories === ['.']) {
                return $declared;
            }
            $segments = explode('\\', $declared);
            if (array_slice($segments, -count($directories)) !== $directories) {
                throw new \TypeError('test target namespace matches its directory path');
            }
            $prefix = implode('\\', array_slice($segments, 0, -count($directories)));
            if ($prefix !== '') {
                return $prefix;
            }
        }
        return '';
    }

    private static function requireAutoload(string $file): void
    {
        if (!preg_match('#^(?:/|[A-Za-z]:[\\\\/])#', $file) || !is_file($file) || !is_readable($file)) {
            throw new \RuntimeException('DCA_TARGET_AUTOLOAD names an absolute path to a readable PHP file, such as /path/to/port/vendor/autoload.php');
        }
        (static function (string $file): void {
            require_once $file;
        })($file);
    }

    private static function registerTargetAutoloader(string $root, string $namespace): void
    {
        spl_autoload_register(static function (string $class) use ($root, $namespace): void {
            if ($namespace !== '') {
                $prefix = $namespace . '\\';
                if (!str_starts_with($class, $prefix)) {
                    return;
                }
                $relative = substr($class, strlen($prefix));
            } else {
                $relative = $class;
            }
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*(?:\\\\[A-Za-z_][A-Za-z0-9_]*)*$/', $relative)) {
                return;
            }
            $path = $root . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $relative) . '.php';
            if (is_file($path)) {
                require_once $path;
            }
        });
    }

    private static function supportsSignature(\ReflectionMethod $method, string $bytesClass): bool
    {
        if ($method->returnsReference() || !self::supportsType($method->getReturnType())) {
            return false;
        }
        foreach ($method->getParameters() as $parameter) {
            if ($parameter->isPassedByReference() || !self::supportsType($parameter->getType(), $bytesClass)) {
                return false;
            }
        }
        return true;
    }

    private static function supportsType(?\ReflectionType $type, ?string $bytesClass = null): bool
    {
        if ($type === null) {
            return true;
        }
        if ($type instanceof \ReflectionUnionType) {
            foreach ($type->getTypes() as $member) {
                if (!self::supportsType($member, $bytesClass)) {
                    return false;
                }
            }
            return true;
        }
        return $type instanceof \ReflectionNamedType
            && (($type->isBuiltin() && in_array($type->getName(), ['array', 'bool', 'float', 'int', 'mixed', 'null', 'string', 'void'], true))
                || ($bytesClass !== null && ltrim($type->getName(), '\\') === $bytesClass));
    }

    /**
     * Reads the three attribute settings. One leading `\` is dropped, because PHP
     * reflection returns class names without it.
     *
     * @return array{module: string, export: string, returnType: string}
     */
    private static function attributeNames(): array
    {
        $names = [];
        foreach (self::ATTRIBUTE_SETTINGS as $key => [$variable, $default]) {
            $names[$key] = self::configuredClass($variable, $default);
        }
        return $names;
    }

    /** Reads one class-name setting, such as an attribute or `DCA_PHP_BYTES_CLASS`. */
    private static function configuredClass(string $variable, string $default): string
    {
        $value = getenv($variable);
        if ($value === false) {
            return $default;
        }
        $name = str_starts_with($value, '\\') ? substr($value, 1) : $value;
        foreach (explode('\\', $name) as $segment) {
            if (!preg_match('/^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$/', $segment)) {
                throw new \InvalidArgumentException("$variable names a PHP class whose segments are identifiers, such as $default");
            }
        }
        return $name;
    }

    /** @return string|array<mixed>|null */
    private static function returnValueType(\ReflectionMethod $method, string $attribute): string|array|null
    {
        $attributes = $method->getAttributes($attribute);
        if ($attributes === []) {
            return null;
        }
        if (count($attributes) !== 1) {
            throw new \TypeError('test target method has one return type marker');
        }
        $arguments = $attributes[0]->getArguments();
        return self::returnShape($arguments['name'] ?? $arguments[0] ?? null);
    }

    /**
     * Checks a return type marker: `Uint8Array`, `record` or `list`; a list of
     * one marker for a list whose every entry has it; or member names mapped to
     * markers for a record, nested to any depth.
     *
     * @return string|array<mixed>
     */
    private static function returnShape(mixed $shape): string|array
    {
        if (is_string($shape) && in_array($shape, ['Uint8Array', 'record', 'list'], true)) {
            return $shape;
        }
        if (is_array($shape) && $shape !== []) {
            if (array_is_list($shape) && count($shape) === 1) {
                self::returnShape($shape[0]);
                return $shape;
            }
            foreach ($shape as $name => $member) {
                if (!is_string($name)) {
                    throw new \TypeError('test target return type names record members or one list entry type');
                }
                self::returnShape($member);
            }
            return $shape;
        }
        throw new \TypeError('test target return type names one supported JavaScript runtime type');
    }

    /**
     * Applies a return type marker to what a test target returned: a marked
     * string becomes bytes and a marked array a record or a list, each then
     * declared to the driver. `null` and the undefined class pass wherever a
     * marker stands; anything else that does not fit is refused.
     *
     * @param string|array<mixed>|null $shape
     */
    private function shaped(string|array|null $shape, mixed $value): mixed
    {
        if ($shape === null || $value === null || $value instanceof $this->undefinedClass) {
            return $value;
        }
        if ($shape === 'Uint8Array') {
            if (is_string($value)) {
                return new BytesValue($value);
            }
            if ($value instanceof $this->bytesClass) {
                return $value;
            }
        } elseif ($shape === 'record') {
            if (is_array($value)) {
                return (object) $value;
            }
            if ($value instanceof \stdClass) {
                return $value;
            }
        } elseif ($shape === 'list') {
            if (is_array($value) && array_is_list($value)) {
                return new ListValue($value);
            }
        } elseif (is_array($shape) && array_is_list($shape)) {
            if (is_array($value) && array_is_list($value)) {
                return new ListValue(array_map(fn (mixed $entry): mixed => $this->shaped($shape[0], $entry), $value));
            }
        } elseif (is_array($value) || $value instanceof \stdClass) {
            $record = new \stdClass();
            foreach ((is_array($value) ? $value : get_object_vars($value)) as $name => $member) {
                $record->{(string) $name} = is_string($name) && array_key_exists($name, $shape)
                    ? $this->shaped($shape[$name], $member)
                    : $member;
            }
            return $record;
        }
        throw new \TypeError('test target return value matches its JavaScript runtime type marker');
    }

    private static function exportName(\ReflectionMethod $method, string $attribute): string
    {
        $attributes = $method->getAttributes($attribute);
        if ($attributes === []) {
            return $method->getName();
        }
        if (count($attributes) !== 1) {
            throw new \TypeError('test target method has one export marker');
        }
        $arguments = $attributes[0]->getArguments();
        $name = $arguments['name'] ?? $arguments[0] ?? null;
        if (!is_string($name) || !preg_match('/^[A-Za-z_$][A-Za-z0-9_$]*$/', $name)) {
            throw new \TypeError('test target export marker names one operation');
        }
        return $name;
    }

    private static function sourceExport(\ReflectionClass $class, string $attribute): ?string
    {
        $attributes = $class->getAttributes($attribute);
        if ($attributes === []) {
            return null;
        }
        if (count($attributes) !== 1) {
            throw new \TypeError('test target class has one export marker');
        }
        $arguments = $attributes[0]->getArguments();
        $name = $arguments['name'] ?? $arguments[0] ?? null;
        if (!is_string($name) || !preg_match('/^[A-Za-z_$][A-Za-z0-9_$]*$/', $name)) {
            throw new \TypeError('test target class export marker names one class');
        }
        return $name;
    }

    private static function stableErrorCode(\Throwable $error): ?string
    {
        if (method_exists($error, 'errorCode')) {
            $method = new \ReflectionMethod($error, 'errorCode');
            if ($method->isPublic() && $method->getNumberOfParameters() === 0) {
                $code = $error->errorCode();
                return is_string($code) ? $code : null;
            }
        }
        $code = $error->getCode();
        return is_string($code) ? $code : null;
    }

    private static function sourceModule(\ReflectionClass $class, string $attribute, string $referenceRoot): ?string
    {
        $attributes = $class->getAttributes($attribute);
        if ($attributes === []) {
            return null;
        }
        if (count($attributes) !== 1) {
            throw new \TypeError('test target class has one module marker');
        }
        $arguments = $attributes[0]->getArguments();
        $path = $arguments['path'] ?? $arguments[0] ?? null;
        self::assertModulePath($path);
        // A typo must not claim nothing while the test runs on the reference.
        $file = realpath($referenceRoot . DIRECTORY_SEPARATOR . $path);
        if (!is_string($file) || !is_file($file) || !str_starts_with($file, $referenceRoot . DIRECTORY_SEPARATOR)) {
            throw new \TypeError("test target module marker $path names no file in the JavaScript reference");
        }
        return $path;
    }

    private static function assertModulePath(mixed $path): void
    {
        if (!is_string($path)
            || !preg_match('/^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\\.m?js$/', $path)
            || in_array('.', explode('/', $path), true)
            || in_array('..', explode('/', $path), true))
            throw new \TypeError('test target module marker is a safe relative JavaScript path');
    }
}
