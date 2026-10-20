<?php

declare(strict_types=1);

namespace Dca\TestBridge;

/**
 * This adapter process's handles. An object of a class discovery claimed
 * crosses as a handle; the same object always gets the same handle, and a
 * handle names its object only in this process. The random session part keeps
 * another process's handle from naming one of these objects.
 */
final class HandleTable
{
    private string $session;
    private int $issued = 0;
    /** @var array<string, object> */
    private array $objects = [];
    /** @var \WeakMap<object, string> */
    private \WeakMap $handles;

    /** @param array<class-string, string> $classes each claimed PHP class and its class ID */
    public function __construct(private readonly array $classes)
    {
        $this->session = bin2hex(random_bytes(8));
        $this->handles = new \WeakMap();
    }

    /**
     * The handle tag of an object of a claimed class, or null for any other
     * object.
     *
     * @return array{'$type': string, class: string, handle: string}|null
     */
    public function tag(object $value): ?array
    {
        $class = $this->classes[get_class($value)] ?? null;
        if ($class === null) {
            return null;
        }
        if (!isset($this->handles[$value])) {
            $this->issued++;
            $handle = 'h-' . $this->session . '-' . $this->issued;
            $this->handles[$value] = $handle;
            $this->objects[$handle] = $value;
        }
        return ['$type' => 'Handle', 'class' => $class, 'handle' => $this->handles[$value]];
    }

    /** The object a handle names in this session. */
    public function resolve(string $class, string $handle): object
    {
        $object = $this->objects[$handle] ?? null;
        if ($object === null) {
            throw new HandleRefusal('bridge handle is not live in this session');
        }
        if (($this->classes[get_class($object)] ?? null) !== $class) {
            throw new HandleRefusal('bridge handle names another class than its object has');
        }
        return $object;
    }

    /** Ends the session: no handle names an object any more. */
    public function release(): void
    {
        $this->objects = [];
        $this->handles = new \WeakMap();
    }
}
