"""One-shot inheritance of an exclusive delegated cgroup-v2 root capability."""

from __future__ import annotations

import array
import os
import select
import socket
import stat
import struct
import sys
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from threading import RLock
from typing import Literal, NoReturn, cast

from .competitive_binding_io import (
    _BindingBackend,
    _filesystem_magic,
    _PinnedDescriptorCgroupBackend,
)
from .competitive_binding_policy import fixed_binding_policy

DELEGATED_ROOT_CONTROL_FD = 4
DELEGATED_ROOT_PROTOCOL_MAGIC = b"MSCBIND1"
DELEGATED_ROOT_PROTOCOL_VERSION = 1
DELEGATED_ROOT_PACKET_BYTES = 88
DELEGATED_ROOT_POLICY_SHA256 = "bd8039119e7ab17b5776fd2025531ff2cd2275ce13c912405792eecc09388e58"
# The supervisor must receive this complete SOCK_SEQPACKET record before it sends
# credentials or authority.  It proves that the coordinator enabled SO_PASSCRED.
DELEGATED_ROOT_RECEIVER_READY = b"R"
DELEGATED_ROOT_RECEIVER_READY_BYTES = len(DELEGATED_ROOT_RECEIVER_READY)
# The supervisor sends this record when its authority is being revoked.  Every
# inbound record is fail-closed, but naming the wire value keeps both peers exact.
DELEGATED_ROOT_SUPERVISOR_REVOKE = b"X"

_DELEGATED_ROOT_HANDSHAKE_TIMEOUT_SECONDS = 30.0

_PACKET_STRUCT = struct.Struct("!8sHHIIIQQ32s16s")
_CREDENTIALS_STRUCT = struct.Struct("=iII")
_INT_BYTES = array.array("i").itemsize
_CGROUP2_SUPER_MAGIC = 0x63677270
_ISSUANCE_LOCK = RLock()
_SCM_RIGHTS = cast(int, getattr(socket, "SCM_RIGHTS", -1))
_AF_UNIX = cast(int, getattr(socket, "AF_UNIX", -1))
_SO_PASSCRED = cast(int, getattr(socket, "SO_PASSCRED", -1))
_MSG_CMSG_CLOEXEC = cast(int, getattr(socket, "MSG_CMSG_CLOEXEC", 0))
_CMSG_SPACE = cast(Callable[[int], int], getattr(socket, "CMSG_SPACE", None))
_GETEUID = cast(Callable[[], int], getattr(os, "geteuid", None))
_GETEGID = cast(Callable[[], int], getattr(os, "getegid", None))
_CLAIMED_CONTROL_IDENTITIES: set[tuple[int, int, int]] = set()

_Recvmsg = Callable[
    [int, int, int],
    tuple[bytes, list[tuple[int, int, bytes]], int, object],
]


def _set_control_timeout(control: socket.socket, timeout: float | None) -> None:
    control.settimeout(timeout)


class DelegatedRootProtocolError(RuntimeError):
    """The inherited supervisor channel or delegated-root packet is invalid."""


class DelegatedRootCapabilityError(RuntimeError):
    """A delegated-root capability is forged, closed, stale, or mismatched."""


@dataclass(frozen=True, slots=True)
class DelegatedRootIdentity:
    device: int
    inode: int

    def __post_init__(self) -> None:
        if type(self.device) is not int or self.device <= 0:
            raise ValueError("delegated-root device identity must be positive")
        if type(self.inode) is not int or self.inode <= 0:
            raise ValueError("delegated-root inode identity must be positive")


@dataclass(frozen=True, slots=True)
class _SupervisorPacket:
    supervisor_pid: int
    supervisor_uid: int
    supervisor_gid: int
    root_identity: DelegatedRootIdentity
    policy_digest: str
    nonce: bytes

    @property
    def session_id(self) -> str:
        return self.nonce.hex()


@dataclass(frozen=True, slots=True)
class _CapabilityAccess:
    backend: _BindingBackend
    root_handle: object
    session_id: str
    root_identity: DelegatedRootIdentity
    policy_digest: str
    production_inherited: bool


@dataclass(frozen=True, slots=True)
class _IssuanceRecord:
    issuing_pid: int
    backend: object
    root_handle: object
    session_id: str
    root_identity: DelegatedRootIdentity
    policy_digest: str
    production_inherited: bool
    control_socket: socket.socket | None


class ExclusiveDelegatedCgroupRoot:
    """An exact-process, non-transferable handle to one pinned delegated root."""

    __slots__ = (
        "__weakref__",
        "_backend",
        "_closed",
        "_control_socket",
        "_issuing_pid",
        "_lock",
        "_policy_digest",
        "_production_inherited",
        "_root_handle",
        "_root_identity",
        "_session_id",
        "_supervisor_gid",
        "_supervisor_pid",
        "_supervisor_uid",
    )

    _backend: object
    _closed: bool
    _control_socket: socket.socket | None
    _issuing_pid: int
    _lock: RLock
    _policy_digest: str
    _production_inherited: bool
    _root_handle: object
    _root_identity: DelegatedRootIdentity
    _session_id: str
    _supervisor_gid: int
    _supervisor_pid: int
    _supervisor_uid: int

    def __new__(cls) -> ExclusiveDelegatedCgroupRoot:
        raise TypeError("ExclusiveDelegatedCgroupRoot cannot be constructed directly")

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def supervisor_pid(self) -> int:
        return self._supervisor_pid

    @property
    def supervisor_uid(self) -> int:
        return self._supervisor_uid

    @property
    def supervisor_gid(self) -> int:
        return self._supervisor_gid

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    @property
    def root_identity(self) -> DelegatedRootIdentity:
        return self._root_identity

    @property
    def binding_eligible(self) -> Literal[False]:
        return False

    @property
    def is_open(self) -> bool:
        with self._lock:
            return not self._closed

    @property
    def is_closed(self) -> bool:
        return not self.is_open

    def __copy__(self) -> NoReturn:
        raise TypeError("delegated-root capabilities cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise TypeError("delegated-root capabilities cannot be deep-copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("delegated-root capabilities cannot be pickled")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        del protocol
        raise TypeError("delegated-root capabilities cannot be pickled")

    def __getstate__(self) -> NoReturn:
        raise TypeError("delegated-root capabilities cannot be pickled")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            cleanup_errors = _close_capability_locked(self)
            if cleanup_errors:
                _raise_error_group("delegated-root capability cleanup failed", cleanup_errors)

    def __enter__(self) -> ExclusiveDelegatedCgroupRoot:
        _require_capability_access(self)
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        exception: BaseException | None,
        _traceback: object,
    ) -> Literal[False]:
        try:
            self.close()
        except BaseException as cleanup_error:
            if exception is None:
                raise
            _raise_error_group(
                "delegated-root capability body and cleanup both failed",
                [exception, cleanup_error],
            )
        return False

    def __del__(self) -> None:
        try:
            if hasattr(self, "_closed"):
                self.close()
        except BaseException:
            pass


_ISSUED: weakref.WeakKeyDictionary[ExclusiveDelegatedCgroupRoot, _IssuanceRecord] = (
    weakref.WeakKeyDictionary()
)
_FORK_LOCKED_CAPABILITIES: list[ExclusiveDelegatedCgroupRoot] = []


def _close_capability_locked(
    capability: ExclusiveDelegatedCgroupRoot,
) -> list[BaseException]:
    """Revoke and close authority while ``capability._lock`` is held."""
    capability._closed = True
    cleanup_errors: list[BaseException] = []
    if capability._production_inherited:
        try:
            cast(_PinnedDescriptorCgroupBackend, capability._backend).close()
        except BaseException as error:
            cleanup_errors.append(error)
    control = capability._control_socket
    capability._control_socket = None
    if control is not None:
        try:
            control.close()
        except BaseException as error:
            cleanup_errors.append(error)
    return cleanup_errors


def _lock_capabilities_before_fork() -> None:
    """Serialize fork behind every operation that can use delegated authority."""
    global _FORK_LOCKED_CAPABILITIES
    _ISSUANCE_LOCK.acquire()
    capabilities = sorted(_ISSUED.keys(), key=id)
    for capability in capabilities:
        capability._lock.acquire()
    _FORK_LOCKED_CAPABILITIES = capabilities


def _unlock_capabilities_after_fork_in_parent() -> None:
    global _FORK_LOCKED_CAPABILITIES
    for capability in reversed(_FORK_LOCKED_CAPABILITIES):
        capability._lock.release()
    _FORK_LOCKED_CAPABILITIES = []
    _ISSUANCE_LOCK.release()


def _revoke_capabilities_after_fork_in_child() -> None:
    """Close inherited kernel authority before child Python can execute."""
    global _FORK_LOCKED_CAPABILITIES
    for capability in _FORK_LOCKED_CAPABILITIES:
        _close_capability_locked(capability)
    _ISSUED.clear()
    for capability in reversed(_FORK_LOCKED_CAPABILITIES):
        capability._lock.release()
    _FORK_LOCKED_CAPABILITIES = []
    _ISSUANCE_LOCK.release()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_lock_capabilities_before_fork,
        after_in_parent=_unlock_capabilities_after_fork_in_parent,
        after_in_child=_revoke_capabilities_after_fork_in_child,
    )


def _revoke_capability_locked(
    capability: ExclusiveDelegatedCgroupRoot,
    reason: str,
) -> NoReturn:
    error = DelegatedRootCapabilityError(reason)
    for cleanup_error in _close_capability_locked(capability):
        error.add_note(
            "authority revocation cleanup also failed: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )
    raise error


def _raise_error_group(context: str, errors: list[BaseException]) -> NoReturn:
    if all(isinstance(error, Exception) for error in errors):
        raise ExceptionGroup(context, cast(list[Exception], errors))
    raise BaseExceptionGroup(context, errors)


def _raise_with_cleanup(
    primary_error: BaseException,
    cleanup_operations: list[Callable[[], object]],
    *,
    context: str,
) -> NoReturn:
    cleanup_errors: list[BaseException] = []
    for operation in cleanup_operations:
        try:
            operation()
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if cleanup_errors:
        _raise_error_group(context, [primary_error, *cleanup_errors])
    raise primary_error.with_traceback(primary_error.__traceback__)


def _parse_supervisor_packet(payload: bytes) -> _SupervisorPacket:
    """Parse the fixed network-order header without using platform socket features."""
    if type(payload) is not bytes:
        raise TypeError("delegated-root packet must be exact bytes")
    if len(payload) != DELEGATED_ROOT_PACKET_BYTES:
        raise DelegatedRootProtocolError(
            f"delegated-root packet must be exactly {DELEGATED_ROOT_PACKET_BYTES} bytes"
        )
    (
        magic,
        version,
        flags,
        supervisor_pid,
        supervisor_uid,
        supervisor_gid,
        root_device,
        root_inode,
        policy_digest,
        nonce,
    ) = _PACKET_STRUCT.unpack(payload)
    if magic != DELEGATED_ROOT_PROTOCOL_MAGIC:
        raise DelegatedRootProtocolError("delegated-root packet magic is invalid")
    if version != DELEGATED_ROOT_PROTOCOL_VERSION:
        raise DelegatedRootProtocolError("delegated-root packet version is unsupported")
    if flags != 0:
        raise DelegatedRootProtocolError("delegated-root packet flags must be zero")
    if supervisor_pid == 0:
        raise DelegatedRootProtocolError("supervisor PID must be nonzero")
    if root_device == 0 or root_inode == 0:
        raise DelegatedRootProtocolError("delegated-root identity must be nonzero")
    expected_digest = bytes.fromhex(DELEGATED_ROOT_POLICY_SHA256)
    if policy_digest != expected_digest:
        raise DelegatedRootProtocolError("delegated-root packet policy digest is invalid")
    if nonce == bytes(16):
        raise DelegatedRootProtocolError("delegated-root session nonce must be nonzero")
    return _SupervisorPacket(
        supervisor_pid=supervisor_pid,
        supervisor_uid=supervisor_uid,
        supervisor_gid=supervisor_gid,
        root_identity=DelegatedRootIdentity(root_device, root_inode),
        policy_digest=policy_digest.hex(),
        nonce=nonce,
    )


def _received_descriptors_and_credentials(
    ancillary: list[tuple[int, int, bytes]],
) -> tuple[list[int], tuple[int, int, int]]:
    rights: list[int] = []
    credentials: list[tuple[int, int, int]] = []
    unknown = False
    scm_credentials = getattr(socket, "SCM_CREDENTIALS", None)
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == _SCM_RIGHTS:
            if len(data) == 0 or len(data) % _INT_BYTES:
                unknown = True
                continue
            values = array.array("i")
            values.frombytes(data)
            rights.extend(int(value) for value in values)
        elif scm_credentials is not None and level == socket.SOL_SOCKET and kind == scm_credentials:
            if len(data) != _CREDENTIALS_STRUCT.size:
                unknown = True
                continue
            credentials.append(_CREDENTIALS_STRUCT.unpack(data))
        else:
            unknown = True
    if unknown or len(ancillary) != 2:
        raise DelegatedRootProtocolError("delegated-root packet has extra ancillary messages")
    if len(rights) != 1:
        raise DelegatedRootProtocolError("delegated-root packet must carry exactly one descriptor")
    if len(credentials) != 1:
        raise DelegatedRootProtocolError("delegated-root packet needs one kernel credential")
    return rights, credentials[0]


def _validate_root_descriptor(descriptor: int, identity: DelegatedRootIdentity) -> None:
    if os.get_inheritable(descriptor):
        raise DelegatedRootProtocolError("delegated-root descriptor is not close-on-exec")
    status = os.fstat(descriptor)
    if not stat.S_ISDIR(status.st_mode):
        raise DelegatedRootProtocolError("delegated-root descriptor is not a directory")
    if status.st_ino == 0:
        raise DelegatedRootProtocolError("delegated-root descriptor has no stable inode")
    if _filesystem_magic(descriptor) != _CGROUP2_SUPER_MAGIC:
        raise DelegatedRootProtocolError("delegated-root descriptor is not cgroup v2")
    if (status.st_dev, status.st_ino) != (identity.device, identity.inode):
        raise DelegatedRootProtocolError("delegated-root descriptor identity mismatches header")


def _initialize_capability(
    packet: _SupervisorPacket,
    *,
    backend: object,
    root_handle: object,
    control_socket: socket.socket | None,
    production_inherited: bool,
) -> ExclusiveDelegatedCgroupRoot:
    capability = object.__new__(ExclusiveDelegatedCgroupRoot)
    capability._backend = backend
    capability._root_handle = root_handle
    capability._control_socket = control_socket
    capability._production_inherited = production_inherited
    capability._closed = False
    capability._lock = RLock()
    capability._issuing_pid = os.getpid()
    capability._session_id = packet.session_id
    capability._supervisor_pid = packet.supervisor_pid
    capability._supervisor_uid = packet.supervisor_uid
    capability._supervisor_gid = packet.supervisor_gid
    capability._policy_digest = packet.policy_digest
    capability._root_identity = packet.root_identity
    record = _IssuanceRecord(
        issuing_pid=capability._issuing_pid,
        backend=backend,
        root_handle=root_handle,
        session_id=capability.session_id,
        root_identity=capability.root_identity,
        policy_digest=capability.policy_digest,
        production_inherited=production_inherited,
        control_socket=control_socket,
    )
    with _ISSUANCE_LOCK:
        _ISSUED[capability] = record
    return capability


def _control_channel_has_event(control: socket.socket) -> bool:
    """Check for data, EOF, HUP, or error without receiving ancillary rights."""
    if control.fileno() < 0:
        return True
    try:
        if control.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
            return True
        readable, _writable, exceptional = select.select(
            [control],
            [],
            [control],
            0.0,
        )
    except (OSError, ValueError):
        return True
    return bool(readable or exceptional)


@contextmanager
def _locked_capability_access(capability: object) -> Iterator[_CapabilityAccess]:
    """Validate authority and retain its lock across a production operation."""
    if type(capability) is not ExclusiveDelegatedCgroupRoot:
        raise DelegatedRootCapabilityError("an exact issued delegated-root capability is required")
    exact = capability
    with _ISSUANCE_LOCK:
        record = _ISSUED.get(exact)
    if record is None:
        raise DelegatedRootCapabilityError("delegated-root capability was not issued here")
    with exact._lock:
        if exact._closed:
            raise DelegatedRootCapabilityError("delegated-root capability is closed")
        if exact._issuing_pid != os.getpid() or record.issuing_pid != os.getpid():
            raise DelegatedRootCapabilityError(
                "delegated-root capability belongs to another process"
            )
        if (
            exact._backend is not record.backend
            or exact._root_handle is not record.root_handle
            or exact._session_id != record.session_id
            or exact._root_identity != record.root_identity
            or exact._policy_digest != record.policy_digest
            or exact._production_inherited is not record.production_inherited
            or exact._control_socket is not record.control_socket
            or exact._policy_digest != fixed_binding_policy().policy_sha256
        ):
            raise DelegatedRootCapabilityError("delegated-root capability state is mismatched")
        if record.production_inherited:
            control = record.control_socket
            if control is None or _control_channel_has_event(control):
                _revoke_capability_locked(
                    exact,
                    "native supervisor control channel is stale or contains unexpected data",
                )
            backend = cast(_PinnedDescriptorCgroupBackend, record.backend)
            backend.validate_root(record.root_handle)
        yield _CapabilityAccess(
            backend=cast(_BindingBackend, record.backend),
            root_handle=record.root_handle,
            session_id=record.session_id,
            root_identity=record.root_identity,
            policy_digest=record.policy_digest,
            production_inherited=record.production_inherited,
        )


def _require_capability_access(capability: object) -> _CapabilityAccess:
    """Take a validated authority snapshot for metadata-only callers and tests."""
    with _locked_capability_access(capability) as access:
        return access


def _claim_control_descriptor() -> None:
    try:
        status = os.fstat(DELEGATED_ROOT_CONTROL_FD)
    except OSError as error:
        raise DelegatedRootProtocolError(
            "delegated-root control descriptor is unavailable"
        ) from error
    identity = (status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode))
    if identity in _CLAIMED_CONTROL_IDENTITIES:
        raise DelegatedRootProtocolError(
            "delegated-root control descriptor was already claimed in this process"
        )
    _CLAIMED_CONTROL_IDENTITIES.add(identity)


def inherit_exclusive_delegated_root() -> ExclusiveDelegatedCgroupRoot:
    """Consume Linux fd 4 and one exact authenticated delegated-root packet."""
    if not sys.platform.startswith("linux"):
        raise DelegatedRootProtocolError("delegated-root inheritance requires Linux")
    required_socket_features = (
        "SO_PASSCRED",
        "SCM_CREDENTIALS",
        "MSG_CMSG_CLOEXEC",
        "MSG_TRUNC",
        "MSG_CTRUNC",
    )
    if any(not hasattr(socket, name) for name in required_socket_features):
        raise DelegatedRootProtocolError("host lacks required Linux credential socket features")

    # Holding the issuance lock through receive and cleanup serializes fork and
    # concurrent inheritance around every descriptor installed by recvmsg.
    with _ISSUANCE_LOCK:
        _claim_control_descriptor()
        return _inherit_exclusive_delegated_root_locked()


def _inherit_exclusive_delegated_root_locked() -> ExclusiveDelegatedCgroupRoot:
    """Perform the one-shot receive while the issuance/fork lock is held."""

    control: socket.socket | None = None
    received: list[int] = []
    backend: _PinnedDescriptorCgroupBackend | None = None
    try:
        try:
            control = socket.socket(fileno=DELEGATED_ROOT_CONTROL_FD)
        except BaseException as wrap_error:
            _raise_with_cleanup(
                wrap_error,
                [lambda: os.close(DELEGATED_ROOT_CONTROL_FD)],
                context="control socket wrapping and cleanup both failed",
            )
        assert control is not None
        os.set_inheritable(control.fileno(), False)
        if control.family != _AF_UNIX:
            raise DelegatedRootProtocolError("delegated-root control fd must be AF_UNIX")
        if control.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
            raise DelegatedRootProtocolError("delegated-root control fd must be SOCK_SEQPACKET")
        try:
            control.getpeername()
        except OSError as error:
            raise DelegatedRootProtocolError(
                "delegated-root control socket is not connected"
            ) from error
        control.setsockopt(socket.SOL_SOCKET, _SO_PASSCRED, 1)
        _set_control_timeout(control, _DELEGATED_ROOT_HANDSHAKE_TIMEOUT_SECONDS)
        ready_flags = cast(int, getattr(socket, "MSG_NOSIGNAL", 0))
        try:
            ready_bytes = control.send(DELEGATED_ROOT_RECEIVER_READY, ready_flags)
            if ready_bytes != DELEGATED_ROOT_RECEIVER_READY_BYTES:
                raise DelegatedRootProtocolError(
                    "delegated-root receiver-ready record was not sent exactly"
                )

            ancillary_bytes = _CMSG_SPACE(_INT_BYTES) + _CMSG_SPACE(_CREDENTIALS_STRUCT.size)
            recvmsg = cast(_Recvmsg, getattr(control, "recvmsg", None))
            payload, ancillary, message_flags, _address = recvmsg(
                DELEGATED_ROOT_PACKET_BYTES,
                ancillary_bytes,
                _MSG_CMSG_CLOEXEC,
            )
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == _SCM_RIGHTS:
                    values = array.array("i")
                    complete = len(data) - (len(data) % _INT_BYTES)
                    values.frombytes(data[:complete])
                    received.extend(int(value) for value in values)
        except TimeoutError as error:
            raise DelegatedRootProtocolError(
                "delegated-root supervisor handshake timed out"
            ) from error
        _set_control_timeout(control, None)
        if message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise DelegatedRootProtocolError(
                "delegated-root packet or ancillary data was truncated"
            )
        packet = _parse_supervisor_packet(payload)
        parsed_descriptors, credentials = _received_descriptors_and_credentials(ancillary)
        if parsed_descriptors != received:
            raise DelegatedRootProtocolError("delegated-root descriptor parsing is inconsistent")

        peer_pid, peer_uid, peer_gid = credentials
        expected_uid = _GETEUID()
        expected_gid = _GETEGID()
        if peer_pid <= 0 or peer_uid < 0 or peer_gid < 0:
            raise DelegatedRootProtocolError("kernel supervisor credentials are out of range")
        if (peer_pid, peer_uid, peer_gid) != (
            packet.supervisor_pid,
            packet.supervisor_uid,
            packet.supervisor_gid,
        ):
            raise DelegatedRootProtocolError("kernel credentials mismatch delegated-root header")
        if peer_uid != expected_uid or peer_gid != expected_gid:
            raise DelegatedRootProtocolError("supervisor is not the dedicated service identity")

        # Readiness is deliberately checked without recv/recvmsg: even MSG_PEEK can
        # install a queued SCM_RIGHTS descriptor in this process on Linux.
        if _control_channel_has_event(control):
            raise DelegatedRootProtocolError("control channel has a trailing packet or closed peer")

        root_fd = received[0]
        _validate_root_descriptor(root_fd, packet.root_identity)
        backend = _PinnedDescriptorCgroupBackend(
            root_fd,
            expected_device=packet.root_identity.device,
            expected_inode=packet.root_identity.inode,
            raise_combined_failures=_raise_backend_failures,
        )
        root_handle = backend.root_handle
        received.pop()
        os.close(root_fd)
        capability = _initialize_capability(
            packet,
            backend=backend,
            root_handle=root_handle,
            control_socket=control,
            production_inherited=True,
        )
        backend = None
        control = None
        return capability
    except BaseException as primary_error:
        cleanup: list[Callable[[], object]] = []
        while received:
            descriptor = received.pop()
            cleanup.append(partial(os.close, descriptor))
        if backend is not None:
            cleanup.append(backend.close)
        if control is not None:
            cleanup.append(control.close)
        _raise_with_cleanup(
            primary_error,
            cleanup,
            context="delegated-root inheritance and descriptor cleanup both failed",
        )


def _raise_backend_failures(
    context: str,
    *,
    primary_error: BaseException,
    cleanup_error: BaseException,
) -> NoReturn:
    _raise_error_group(context, [primary_error, cleanup_error])


def _issue_capability_for_testing(
    *,
    backend: object,
    root_handle: object,
    root_device: int = 1,
    root_inode: int = 1,
    nonce: bytes = bytes.fromhex("00112233445566778899aabbccddeeff"),
) -> ExclusiveDelegatedCgroupRoot:
    """Issue a non-production test value; production mutation rejects its provenance."""
    if type(nonce) is not bytes or len(nonce) != 16 or nonce == bytes(16):
        raise ValueError("test nonce must be exactly 16 nonzero bytes")
    packet = _SupervisorPacket(
        supervisor_pid=os.getpid(),
        supervisor_uid=getattr(os, "geteuid", lambda: 0)(),
        supervisor_gid=getattr(os, "getegid", lambda: 0)(),
        root_identity=DelegatedRootIdentity(root_device, root_inode),
        policy_digest=DELEGATED_ROOT_POLICY_SHA256,
        nonce=nonce,
    )
    return _initialize_capability(
        packet,
        backend=backend,
        root_handle=root_handle,
        control_socket=None,
        production_inherited=False,
    )


assert _PACKET_STRUCT.size == DELEGATED_ROOT_PACKET_BYTES
