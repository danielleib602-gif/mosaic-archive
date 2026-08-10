# Native binding-supervisor protocol

Status: experimental, Linux x86-64, non-binding.

This protocol transfers one fresh cgroup-v2 session-root descriptor from the
native benchmark supervisor to the trusted Python coordinator. It authorizes
descriptor-relative creation, configuration, verification, and cleanup of
benchmark leaf cgroups. It does **not** authorize post-spawn process attachment,
launch a measured workload, or make any result eligible for Competitive
Contract v1 or a stable release.

## Trust and inherited descriptors

A trusted host provisioner creates a connected `AF_UNIX` `SOCK_SEQPACKET`
socket pair and opens an exclusive delegated cgroup-v2 parent. It starts the
native supervisor with the parent at descriptor 3 and one socket endpoint at
descriptor 4. It starts the trusted Python coordinator with the other socket
endpoint at descriptor 4. Neither descriptor is exposed to a measured tool.

The provisioner, native supervisor, and Python coordinator run as one dedicated
service identity, in the same PID and user namespaces, with no unrelated
same-identity processes. The namespace requirement makes the packet's
sender-local PID/UID/GID representation identical to the receiver-visible
kernel `SCM_CREDENTIALS` representation. A future launcher must run measured
tools under a different UID or a mount namespace that cannot access the
delegated cgroup tree. Pathnames and advisory locks do not establish this
boundary.

The supervisor accepts no cgroup pathname. It validates the inherited parent
descriptor as cgroup v2, creates a fresh unpredictable session child, enables
exactly the fixed `cpuset`, `memory`, and `pids` delegation, rejects an inherited
parent with any other controller already enabled, and retains the parent
descriptor for cleanup. The coordinator enables `SO_PASSCRED` and then sends one
exact ready byte (`0x52`, ASCII `R`). The supervisor waits for that byte before
sending the handoff, so the kernel attaches the sender's credentials to the
packet without a queued-packet race. The coordinator bounds the complete ready
and handoff exchange to 30 seconds; timeout closes the channel and transfers no
lasting authority.

## Handoff packet

Exactly one 88-byte network-byte-order packet is sent with exactly one
`SCM_RIGHTS` descriptor. The kernel-added ancillary data must contain exactly
one `SCM_CREDENTIALS` record. The packet layout is:

| Offset | Bytes | Field | Required value |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `MSCBIND1` |
| 8 | 2 | version | unsigned integer `1` |
| 10 | 2 | flags | unsigned integer `0` |
| 12 | 4 | supervisor PID | exact positive sender PID |
| 16 | 4 | supervisor UID | exact sender and service UID |
| 20 | 4 | supervisor GID | exact sender and service GID |
| 24 | 8 | root device | received descriptor `st_dev` |
| 32 | 8 | root inode | received descriptor nonzero `st_ino` |
| 40 | 32 | policy digest | raw SHA-256 bytes for the fixed nested runner policy |
| 72 | 16 | session nonce | unpredictable nonzero bytes |

The fixed policy digest is
`bd8039119e7ab17b5776fd2025531ff2cd2275ce13c912405792eecc09388e58`.
The lowercase hexadecimal nonce is the process-local session identifier and is
also embedded in the native session-directory name.

The coordinator receives with `MSG_CMSG_CLOEXEC` and rejects truncated data or
ancillary storage, a wrong packet size, any unsupported field, missing or extra
ancillary records, more or fewer than one descriptor, mismatched credentials,
a policy mismatch, a non-directory descriptor, a non-cgroup-v2 descriptor, or
root device/inode mismatch. Installed rights are placed under cleanup ownership
immediately after `recvmsg`, before any later operation can fail, and every
received descriptor is closed exactly once on failure. No field supplied by the
sender can override the fixed policy. The coordinator checks for trailing data,
EOF, or error with readiness polling rather than `recv` or `MSG_PEEK`, because
even peeking at a rejected rights-bearing packet can install a descriptor.

## Capability and cleanup lifecycle

After validation, the coordinator wraps the session-root descriptor and live
control socket in a non-copyable, context-managed
`ExclusiveDelegatedCgroupRoot`. The object is process-issued misuse hardening;
the kernel descriptor, isolated service identity, and living native supervisor
are the authority. All capability, qualification, lease, and measurement
objects remain `binding_eligible=false`.

The coordinator claims each fixed control-socket identity once per process and
holds its issuance/fork lock across the complete receive and failure cleanup.
A duplicate or concurrent inheritance attempt therefore fails before wrapping
or closing the live FD 4, and a concurrent `fork()` cannot inherit an untracked
rights descriptor between `recvmsg` and capability registration.

A capability-based qualification may create a fresh configured leaf. The exact
capability, backend, root identity, policy digest, and session identity must all
match before the first mutation. A path-qualified diagnostic result can never
be upgraded into mutation authority. Production `attach_process` remains
disabled because writing a PID after spawn has a race before accounting and
containment begin.

Every production root or leaf operation holds the exact capability's process
lock while it revalidates the retained control channel and pinned root. EOF,
socket error, or any inbound byte revokes authority before backend access. Lease
objects also retain the issuing PID and cannot be used after `fork()`. Capability
closure is serialized behind in-flight operations, so ordinary coordinator
shutdown cannot race native cleanup against a Python mutation.

Closing the capability closes the control endpoint. On a handled termination
signal, the native supervisor sends one revoke byte (`0x58`, ASCII `X`) and waits
for coordinator EOF; it does not begin cleanup while coordinator authority may
be in use. The next capability check observes the byte, revokes locally, and
closes the endpoint. Unexpected records, zero-length records, ancillary data,
socket failures, and half-close are protocol errors, not EOF. After a possible
handoff the supervisor records the primary error, sends revocation when possible,
and continues the barrier until full peer closure is proven. If closure cannot
be proven, it suppresses automatic cleanup and leaves the named session visible
for recovery rather than racing retained coordinator authority. After verified
EOF the supervisor requests recursive termination
with `cgroup.kill`, waits a fixed bounded interval for `cgroup.events` to report
`populated 0`, removes only validated direct benchmark leaves, and removes the
session root through the retained parent descriptor. Cleanup failure is a hard
error and leaves the session visible for recovery. `SIGKILL` cannot be handled;
a future host provisioner must reconcile stale session roots before reuse.

Normal Linux CI runs the portable and socket-level native tests, provisions a
real delegated cgroup-v2 parent for the opt-in direct lifecycle test, then starts
the release supervisor on exact descriptors 3 and 4. The production Python
receiver completes READY, authenticated handoff, qualification, real leaf
configuration/removal, capability closure, EOF-barrier cleanup, and supervisor
exit under bounded timeouts. The same workspace is still checked and linted on
Windows, but only the Linux gate can establish cgroup syscall behavior.

## Remaining authoritative-runner work

The fixed design and phased verification boundary for this work is recorded in
`NATIVE_LAUNCHER_DESIGN.md`. It does not alter `MSCBIND1` or grant binding
authority to the current supervisor. The internal clone3 ABI probe covers only
the exact flag layout, namespace PID 1, initial placement in an inherited empty
leaf, and bounded pidfd reaping; it does not execute a payload.

The next native stage must use a single-threaded, immediate-exec
`clone3(CLONE_INTO_CGROUP | CLONE_NEWPID | CLONE_PIDFD)` path. It must also
isolate the cgroup mount, run a PID-namespace reaper, capture all descendant
executable identities and bounded output, prewarm the exact immutable input
outside the measured cgroup, verify the round trip, and sign the raw run record.
Only that complete boundary can be evaluated for binding evidence.
