# Shared alternate implementations

An alternate implementation moves here when two or more experiments use it, and
it moves as a whole directory. Take an experiment elsewhere without the
directories it imports from here and it fails at load. An alternate
implementation never imports another, so a directory here imports only the
standard tree. An implementation that one experiment uses stays in that
experiment's own `implementation/`.

`bind-on-authority/keySealing.js` imports the `bind.js` beside it, which names
the same construction, so the two move together.
