# Mosaic binding supervisor

This Linux x86-64 binary is the first native delegated-cgroup lifecycle slice.
It accepts no cgroup pathname: an already-open exclusive delegated cgroup-v2
parent must arrive as FD 3 and a connected `AF_UNIX` `SOCK_SEQPACKET` endpoint
as FD 4. The binary creates a fresh direct session child, enables the fixed
`cpuset`, `memory`, and `pids` delegation while rejecting extra enabled
controllers, waits for the coordinator's `SO_PASSCRED` ready byte, transfers the
session descriptor in the one-shot `MSCBIND1` handoff, and remains responsible
for cleanup.

The normal supervisor mode is deliberately non-authoritative. It does not
launch or attach a workload and cannot make a measurement binding-eligible.

An explicitly opt-in `--internal-clone3-abi-probe` diagnostic is the sole
exception to the normal supervisor mode. It accepts no path or command and
consumes an already-open empty cgroup-v2 leaf on FD 3. The probe uses the exact
`CLONE_INTO_CGROUP | CLONE_NEWPID | CLONE_PIDFD` flags, confirms namespace PID 1
and exact initial leaf placement, releases over a fixed control channel, and
signals/reaps only through the pidfd under fixed timeouts. It does not execute a
workload, create or remove the leaf, alter `MSCBIND1`, or produce
binding-eligible evidence.

Normal shutdown is control-channel EOF. `SIGTERM`, `SIGINT`, or `SIGHUP`
received through `signalfd` first sends a revocation byte and waits for peer EOF,
so cleanup cannot race an in-flight coordinator operation. Cleanup recursively
requests termination with `cgroup.kill`, waits boundedly for the session to
become unpopulated, removes only validated direct `mosaic-binding-` leaves, and
removes the session through the retained parent descriptor. `SIGKILL` cannot be
handled; the trusted host provisioner must reconcile stale
`mosaic-supervisor-*` session roots after a forced kill before reusing the
delegated parent.

After handoff, unexpected, empty, truncated, ancillary-bearing, and half-close
traffic is never treated as EOF. The supervisor requests revocation and waits
for verified full peer closure before cleanup. If a local control failure makes
that proof impossible, automatic cleanup is disarmed and the named session is
left visible for trusted-host recovery.
