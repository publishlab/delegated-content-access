// @ts-check
//
// The names every object carries whether anything wrote them or not. They
// pass the grammars (they are ordinary lowercase words), and a plain-object
// lookup finds them on the prototype, so every consumer that walks a map keyed
// by a name off the wire has to stay inert on all five.
//
// One list rather than a copy per file: a file checking four of them and the
// file beside it checking three were making two different claims out of the
// same intent, and the one that dropped `isPrototypeOf` was the weaker.
//
// `__proto__` is not in here. It is the one inherited name that is a setter on
// an object literal, so it is a different failure: an assignment that moves the
// prototype rather than a read that finds one, and a test about it says so
// where it tests it.

export const INHERITED = ["constructor", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf"];
