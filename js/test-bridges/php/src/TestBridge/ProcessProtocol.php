<?php

declare(strict_types=1);

namespace Dca\TestBridge;

final class ProcessProtocol
{
    private const MAXIMUM_FRAME_BYTES = 1048576;

    /** @param callable(\stdClass): array<string, mixed> $handler */
    public static function serve(callable $handler): void
    {
        while (($header = self::readExact(STDIN, 4)) !== null) {
            $size = unpack('Nsize', $header)['size'];
            if ($size > self::MAXIMUM_FRAME_BYTES) {
                throw new \RangeException('bridge frame exceeds maximum');
            }
            $body = self::readExact(STDIN, $size);
            if ($body === null) {
                throw new \UnexpectedValueException('bridge stream ended mid-frame');
            }
            try {
                $request = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
                if (!$request instanceof \stdClass) {
                    throw new \TypeError('bridge request is an object');
                }
                self::write($handler($request));
            } catch (\Throwable $error) {
                fwrite(STDERR, "bridge protocol failure: {$error->getMessage()}\n");
                exit(2);
            }
        }
    }

    public static function assertRequest(\stdClass $request): void
    {
        if (($request->version ?? null) !== 1 || !is_string($request->id ?? null) || $request->id === '') {
            throw new \TypeError('bridge request has protocol version and id');
        }
        if (!in_array($request->type ?? null, ['describe', 'describeModule', 'call', 'dispose'], true)) {
            throw new \TypeError('bridge request type is known');
        }
        if (($request->type ?? null) === 'describeModule' && !is_string($request->sourceModule ?? null)) {
            throw new \TypeError('bridge module description has a source module');
        }
        if (($request->type ?? null) === 'call' && property_exists($request, 'target')) {
            throw new \TypeError('bridge call names its protocol in protocol, not target');
        }
        if (($request->type ?? null) === 'call' && (($request->protocol ?? null) !== 'dca-test-bridge/v1' || !is_string($request->operation ?? null) || !property_exists($request, 'input'))) {
            throw new \TypeError('bridge call has protocol, operation, and input');
        }
        if (($request->type ?? null) === 'call' && property_exists($request, 'receiver') && !self::isHandle($request->receiver)) {
            throw new \TypeError('bridge call receiver is one handle');
        }
    }

    /** Whether `$value` has the exact handle layout. */
    private static function isHandle(mixed $value): bool
    {
        if (!$value instanceof \stdClass) {
            return false;
        }
        $members = get_object_vars($value);
        $names = array_keys($members);
        sort($names);
        $exact = $names === ['$type', 'class', 'handle'];
        $tagged = ($members['$type'] ?? null) === 'Handle';
        $named = is_string($members['class'] ?? null) && $members['class'] !== '';
        $issued = is_string($members['handle'] ?? null) && $members['handle'] !== '';
        return $exact && $tagged && $named && $issued;
    }

    /** @param array<string, mixed> $result @return array<string, mixed> */
    public static function response(string $id, array $result): array
    {
        return ['version' => 1, 'type' => 'response', 'id' => $id, 'result' => $result];
    }

    /** @return resource|null */
    private static function readExact($stream, int $length)
    {
        $result = '';
        while (strlen($result) < $length && !feof($stream)) {
            $chunk = fread($stream, $length - strlen($result));
            if ($chunk === false) {
                throw new \RuntimeException('bridge stream could not be read');
            }
            $result .= $chunk;
        }
        if ($result === '' && $length > 0 && feof($stream)) {
            return null;
        }
        return strlen($result) === $length ? $result : null;
    }

    /** @param array<string, mixed> $value */
    private static function write(array $value): void
    {
        $json = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $frame = pack('N', strlen($json)) . $json;
        for ($offset = 0; $offset < strlen($frame);) {
            $written = fwrite(STDOUT, substr($frame, $offset));
            if ($written === false || $written === 0) {
                throw new \RuntimeException('bridge frame could not be written');
            }
            $offset += $written;
        }
        fflush(STDOUT);
    }
}
