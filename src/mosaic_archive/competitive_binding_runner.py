"""Fail-closed cgroup-v2 foundations for future binding benchmark evidence.

This compatibility facade preserves the established runner import path while the host
qualification, control primitives, and cgroup lease lifecycle live in focused modules.
The implementation deliberately stops short of launching measured processes, so every
value exposed here remains structurally non-binding.
"""

from __future__ import annotations

from . import competitive_binding_cgroup as _cgroup
from . import competitive_binding_common as _common
from . import competitive_binding_io as _io
from . import competitive_binding_policy as _policy
from . import competitive_binding_qualification as _qualification
from . import competitive_binding_supervisor as _supervisor

_MAX_SIGNED_64 = _cgroup._MAX_SIGNED_64
_POSITIVE_INTEGER_RE = _cgroup._POSITIVE_INTEGER_RE
BindingCgroupLease = _cgroup.BindingCgroupLease
_create_binding_cgroup_for_testing = _cgroup._create_binding_cgroup_for_testing
_create_configured_binding_cgroup = _cgroup._create_configured_binding_cgroup
create_binding_cgroup = _cgroup.create_binding_cgroup

_CPUSET_COMPONENT_RE = _common._CPUSET_COMPONENT_RE
_MAX_CPUSET_ITEMS = _common._MAX_CPUSET_ITEMS
BindingRunnerCleanupError = _common.BindingRunnerCleanupError
BindingRunnerHostError = _common.BindingRunnerHostError
_backend_call = _common._backend_call
_control_scalar = _common._control_scalar
_controller_names = _common._controller_names
_format_id_set = _common._format_id_set
_parse_id_set = _common._parse_id_set
_raise_combined_failures = _common._raise_combined_failures
_single_line = _common._single_line
_verify_effective_id_set = _common._verify_effective_id_set
_write_and_verify = _common._write_and_verify
_write_exact = _common._write_exact

_MAX_CONTROL_BYTES = _io._MAX_CONTROL_BYTES
_BindingBackend = _io._BindingBackend
_DescriptorRelativeFilesystemBackend = _io._DescriptorRelativeFilesystemBackend
_validate_leaf_name = _io._validate_leaf_name

_REQUIRED_CONTROLLERS = _policy._REQUIRED_CONTROLLERS
_THREAD_TIERS = _policy._THREAD_TIERS
BindingRunnerPolicy = _policy.BindingRunnerPolicy
fixed_binding_policy = _policy.fixed_binding_policy

BindingHostFacts = _qualification.BindingHostFacts
BindingHostQualification = _qualification.BindingHostQualification
_FilesystemBindingBackend = _qualification._FilesystemBindingBackend
_qualify_pinned_root = _qualification._qualify_pinned_root
_validate_requested_threads = _qualification._validate_requested_threads
qualify_binding_host = _qualification.qualify_binding_host
qualify_supervised_binding_host = _qualification.qualify_supervised_binding_host

DelegatedRootCapabilityError = _supervisor.DelegatedRootCapabilityError
DelegatedRootIdentity = _supervisor.DelegatedRootIdentity
ExclusiveDelegatedCgroupRoot = _supervisor.ExclusiveDelegatedCgroupRoot
_locked_capability_access = _supervisor._locked_capability_access
