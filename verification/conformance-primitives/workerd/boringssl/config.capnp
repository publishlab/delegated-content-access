# The workerd configuration `bridge` runs with `workerd test`: one Worker, no
# socket, no listener. `bridge` copies this file, `worker.mjs` and the shared
# `answer.mjs` into a fresh temp directory and writes the batch from stdin to
# `batch.txt` there, so every `embed` below resolves inside that directory.

using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [ (name = "main", worker = .bridgeWorker) ],
);

const bridgeWorker :Workerd.Worker = (
  modules = [
    (name = "worker.mjs", esModule = embed "worker.mjs"),
    (name = "answer.mjs", esModule = embed "answer.mjs"),
    (name = "batch.txt", text = embed "batch.txt"),
  ],
  # The compatibility date pins which workerd behaviours the Worker gets, the
  # way the release pins the binary. answer.mjs needs the global `Buffer`, which
  # nodejs_compat provides, and nodejs_compat is on by default from 2026-08-04:
  # on 2026-08-03 `Buffer` is not defined and every batch faults. The flag is not
  # named, because naming a default flag makes workerd print a warning on every
  # run. A pin bump keeps this date unless a newer default changes an answer.
  compatibilityDate = "2026-08-04",
);
