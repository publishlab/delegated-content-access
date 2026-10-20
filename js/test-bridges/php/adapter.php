<?php

declare(strict_types=1);

ini_set('display_errors', 'stderr');
set_error_handler(static function (int $severity, string $message, string $file, int $line): never {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

// The bridge's own classes: prefix Dca\ maps to src/, so Dca\TestBridge\TargetMap
// is src/TestBridge/TargetMap.php.
spl_autoload_register(static function (string $class): void {
    $prefix = 'Dca\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $path = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

use Dca\TestBridge\HandleRefusal;
use Dca\TestBridge\HandleTable;
use Dca\TestBridge\TargetMap;
use Dca\TestBridge\ProcessProtocol;
use Dca\TestBridge\Serializer;

// The adapter ships inside the JavaScript reference it serves, at
// test-bridges/php/, so module paths resolve two levels up.
$map = TargetMap::fromEnvironment(dirname(__DIR__, 2));
// One session: this process, from discovery until dispose or exit. An object
// of a claimed class crosses as a handle that names it only here.
$handles = new HandleTable($map->handleClasses());
$serializer = new Serializer($map->bytesClass(), $map->undefinedClass(), $handles);

ProcessProtocol::serve(static function (stdClass $request) use ($serializer, $map, $handles): array {
    $id = $request->id ?? '';
    try {
        ProcessProtocol::assertRequest($request);
        if ($request->type === 'describe') {
            return ProcessProtocol::response($id, ['kind' => 'observation', 'value' => $serializer->encode([
                'identity' => ['bridge' => 'php', 'adapterVersion' => '1', 'targetVersion' => 'php-test'],
                'capabilities' => ['valueTypes' => $serializer->valueTypes(), 'moduleDiscovery' => true],
                'errorTypes' => $map->errorTypes(),
            ])]);
        }
        if ($request->type === 'dispose') {
            $handles->release();
            return ProcessProtocol::response($id, ['kind' => 'observation', 'value' => null]);
        }
        if ($request->type === 'describeModule') {
            $members = $map->describeModule($request->sourceModule);
            $classes = $map->describeClasses($request->sourceModule);
            $description = ['members' => $members] + ($classes === [] ? [] : ['classes' => $classes]);
            return ProcessProtocol::response($id, ['kind' => 'observation', 'value' => $serializer->encode($description)]);
        }
        // An argument the frame's `instances` marks is the data of a reference
        // class instance. This adapter passes it as the record it arrives as,
        // a stdClass, and rebuilds no class.
        // A handle, at any depth, arrives as the object it names in this
        // session; the product code never sees the handle itself.
        $input = $serializer->decode($request->input);
        if (!is_array($input) || !array_is_list($input)) {
            throw new TypeError('operation input is an argument list');
        }
        $hasReceiver = property_exists($request, 'receiver');
        if ($hasReceiver) {
            $receiver = $serializer->decode($request->receiver);
            $result = $map->invokeMember($request->operation, $receiver, $input);
        } else {
            $result = $map->invoke($request->operation, $input);
        }
        // The test target answered. A result the bridge cannot encode is a
        // limit of the bridge, reported as uncarried, never as a target
        // refusal. Arguments need no check: PHP passes arrays by value and
        // discovery refuses by-reference parameters.
        try {
            [$value, $declared] = $serializer->encodeAnswer($result);
            json_encode($value, JSON_THROW_ON_ERROR);
        } catch (TypeError|JsonException $error) {
            return ProcessProtocol::response($id, ['kind' => 'uncarried', 'message' => $error->getMessage()]);
        }
        // `declared` names the positions whose PHP type says the JavaScript
        // type; the driver reads the rest by the reference type.
        return ProcessProtocol::response($id, ['kind' => 'observation', 'value' => $value] + ($declared === [] ? [] : ['declared' => $declared]));
    } catch (OutOfBoundsException $error) {
        return ProcessProtocol::response($id, ['kind' => 'unsupported']);
    } catch (HandleRefusal $error) {
        return ProcessProtocol::response($id, ['kind' => 'refusal', 'code' => 'adapter_refusal', 'message' => $error->getMessage()]);
    } catch (Throwable $error) {
        $mapped = $map->classify($error);
        if ($mapped !== null) {
            return ProcessProtocol::response($id, ['kind' => 'refusal'] + $mapped);
        }
        return ProcessProtocol::response($id, ['kind' => 'refusal', 'code' => 'adapter_refusal', 'message' => $error->getMessage()]);
    }
});
