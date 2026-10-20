# Conformance (shared answer source)

This directory holds bridge source that more than one lane runs unchanged. It is not a lane: it carries no
`bridge.json` and no `check`, so neither the driver nor `conformance-primitives/check` finds it, and no run
names it.

`js/v1/answer.mjs` answers the contract's seven operations through `globalThis.crypto.subtle`, with `Buffer`
for base64url and hex. It exports two functions. `answerLine` takes the batch text and returns the finished
answer, one JSON line without a trailing newline. `faultLine` takes what `answerLine` threw and returns the
`bridge: ...` diagnostic line, also without a newline. The module touches no `process`, imports no `node:fs`
and writes nothing, so an entry only supplies the batch text, writes one of the two lines and sets the exit.

The AES-GCM and RSA-OAEP opens currently translate every WebCrypto decryption rejection into the operation's
refusal. They do not distinguish authentication or padding failures from a runtime failure at that call.
Success cases expose a runtime unable to decrypt, but those observations produce a disagreement rather than
an incomplete run. This is an implementation limitation; the [contract's distinction between a defined
refusal and an unservable batch](../_shared/contract/v1/bridge.md#what-a-bridge-must-never-do) still applies.

Two entries run it:

- `js/v1/bridge.mjs` is the stdin entry. It reads fd 0, writes the answer line on stdout and exits 0, or
  writes the fault line on stderr and exits 1. Node, Deno and Bun run it.
- `workerd/boringssl/worker.mjs` is the workerd entry. A workerd isolate reads fd 0 as empty and ignores
  `process.exitCode`, so this Worker gets the batch as a text module, writes the answer line with
  `console.log` and throws on a fault to make `workerd test` exit nonzero.

Each JavaScript lane starts its entry under its own pinned runtime through its own `bridge` wrapper:
`node/openssl/bridge` runs `bridge.mjs` on Node, `deno/rustcrypto-awslc/bridge` on Deno and `bun/boringssl/bridge`
on Bun, and `workerd/boringssl/bridge` runs `worker.mjs` with `answer.mjs` on workerd. `answer.mjs` names no
runtime. `bridge.mjs` names Node only in its `#!/usr/bin/env node` line, which lets Node run the file directly;
every lane wrapper starts it with that lane's own binary instead. So which library answers an operation depends
on the runtime a lane starts the source on, and each lane's README names that library.

A lane owns everything around the files: which runtime binary runs them and with which flags, its `bridge.json`
declaration of members and operations, and its `check`. A change here changes every lane that runs it, so run
each of those lanes' checks before committing one.
