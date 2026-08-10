# Native measured-workload launcher design

Status: accepted implementation target; no current result is binding-eligible.

This document fixes the next native boundary after the `MSCBIND1` delegated-root
supervisor. It deliberately does not extend the existing protocol or authorize
Python to attach a process after creation.

## Implemented ABI probe

The opt-in `--internal-clone3-abi-probe` diagnostic consumes only an inherited,
already-open empty cgroup-v2 leaf on FD 3. It uses the exact required clone
flags, confirms the child is namespace PID 1 and the only process in that leaf,
then releases it over the fixed control socket and signals/reaps only through
the returned pidfd under fixed timeouts. Unsupported kernels, missing privilege,
and invalid targets remain distinct fail-closed outcomes. The child never
executes a payload, the probe does not create or remove the caller-owned leaf,
and its output always states `binding_eligible=false`.

## Security invariants

The native launcher must create the measured namespace init with one `clone3`
call using all of:

- `CLONE_INTO_CGROUP`, with an already-open fresh cgroup-v2 leaf descriptor;
- `CLONE_NEWPID`, so the namespace reaper exists from the first instruction;
- `CLONE_PIDFD`, so the outer supervisor never signals a recycled numeric PID;
- `SIGCHLD` as the exit signal, with every other `clone_args` field zero.

There is no `fork()` plus `cgroup.procs` fallback. `ENOSYS`, `E2BIG` from an
older `clone_args` layout, an unsupported flag combination, a syscall filter,
or missing namespace privilege makes the host ineligible. Permission errors
identify a misprovisioned host. Invalid-domain or non-v2 cgroup failures identify
an invalid target. These outcomes must remain distinct in diagnostics and all
remain fail-closed.

The native side will create, configure, verify, and remove measurement leaves.
Python retains orchestration and evidence assembly but never receives a
production process-attachment method. `MSCBIND1` remains byte-for-byte stable;
future launch traffic requires a separately versioned `MSCBIND2` protocol.

## Bounded first implementation slice

The first executable slice is an opt-in native self-test, not an arbitrary
command runner:

1. Create and configure a fresh measurement leaf below the retained session.
2. Invoke `clone3(CLONE_INTO_CGROUP | CLONE_NEWPID | CLONE_PIDFD)`.
3. Have the child normalize fixed descriptors and immediately `execveat` the
   same native binary in an internal namespace-init mode.
4. Have namespace PID 1 launch a fixed built-in test payload, adopt and reap all
   descendants, then emit one exact bounded binary status record.
5. Have the outer process wait through the pidfd, verify the leaf becomes
   unpopulated, capture `memory.peak`, and remove the leaf on every path.

The self-test must prove that the child's first observable state is already in
the target leaf, that PID 1 reaps an orphaned descendant, and that timeout,
overflow, exec failure, and forced cleanup stay bounded. Its result remains
`binding_eligible=false`.

## Post-clone descriptor model

The namespace-init stub admits only these descriptors:

| FD | Purpose |
|---:|---|
| 0 | null input |
| 1 | bounded standard-output pipe |
| 2 | bounded standard-error pipe |
| 3 | sealed binary launch specification |
| 4 | exact namespace-init status channel |
| 5 | `O_PATH` self-executable used by `execveat` |

Every other descriptor is closed before workload execution. The child restores
the intended signal mask and performs only async-signal-safe fixed-FD setup
between `clone3` and `execveat`; failures use `_exit` after writing the fixed
error record.

## Reaping, timeout, and output

Namespace PID 1 never becomes the measured tool. It launches PID 2, records its
status, and calls `waitid` until the namespace has no children. The outer
supervisor owns the PID 1 pidfd and wall timer.

Timeout handling is ordered and bounded:

1. send `SIGTERM` through the pidfd;
2. wait the fixed grace interval;
3. request recursive termination through `cgroup.kill`;
4. send `SIGKILL` through the pidfd if PID 1 remains alive;
5. reap, then require `cgroup.events` to report `populated 0` before removal.

Standard output and error are drained concurrently. Crossing either configured
byte ceiling is a hard failure, not silent truncation: terminate the leaf,
continue draining/reaping, and record the overflow. Large archive output uses a
supervisor-owned descriptor with `RLIMIT_FSIZE` plus final descriptor-relative
size and identity checks. Directory output remains gated until the complete
tree can be bounded and verified.

## Later `MSCBIND2` boundary

A future Python integration may receive a dedicated command endpoint alongside
the retained liveness channel. Each request must bind a session nonce, policy
digest, monotonically increasing request ID, executable digest, exact bounded
argument/environment fields, and an exact ancillary-descriptor count. Paths
are diagnostic only; executable, input, working directory, and output authority
arrive as already-open descriptors.

Before arbitrary tools can run, the launcher must also provide a private mount
namespace with private propagation, an immutable runtime root, a PID-namespace
specific `/proc`, read-only input mounts, one bounded writable output, a
distinct host workload UID/GID, cleared supplementary groups and capabilities,
and `no_new_privs`. Missing mount or identity isolation has no weaker fallback.

## Required verification

- exact `clone_args` size, bits, pointer fields, and zero fields;
- syscall-error classification and unsupported-kernel behavior;
- initial cgroup placement, inner PID identities, and outer pidfd identity;
- orphan adoption, complete reaping, daemonized descendants, and ignored signals;
- exact-limit and limit-plus-one output with mixed-stream backpressure;
- exec-error reporting, inherited-FD leak detection, and cleanup aggregation;
- leaf unpopulation and removal after every success and failure;
- privilege/isolation tests for UID, groups, capabilities, mounts, and read-only input.

Primary Linux references:

- <https://man7.org/linux/man-pages/man2/clone.2.html>
- <https://man7.org/linux/man-pages/man7/pid_namespaces.7.html>
- <https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html>
