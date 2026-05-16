//! ABI-safe data structures shared by userspace wrappers and kernel tests.
//!
//! This module mirrors the draft ABI while `alani-abi` stabilizes. Public
//! structures that can cross the kernel boundary use `#[repr(C)]`,
//! fixed-width integers, version or size fields where needed, reserved fields,
//! and explicit flag validation.

use core::mem::size_of;

use crate::error::{AlaniError, AlaniResult};

/// Current ABI major version.
pub const ALANI_ABI_MAJOR: u16 = 0;
/// Current ABI minor version.
pub const ALANI_ABI_MINOR: u16 = 1;
/// Current ABI patch version.
pub const ALANI_ABI_PATCH: u16 = 0;

/// The ABI exposes syscall table metadata through `sys_info`.
pub const ABI_FEATURE_SYSCALL_TABLE: u64 = 1 << 0;
/// The ABI supports trace context propagation in syscall frames.
pub const ABI_FEATURE_TRACE_CONTEXT: u64 = 1 << 1;
/// The ABI supports capability handles and rights masks.
pub const ABI_FEATURE_CAPABILITY_HANDLES: u64 = 1 << 2;
/// The ABI supports bounded user-buffer descriptors.
pub const ABI_FEATURE_USER_BUFFERS: u64 = 1 << 3;
/// The ABI supports inference budget descriptors.
pub const ABI_FEATURE_INFERENCE_BUDGETS: u64 = 1 << 4;
/// The ABI supports audit syscall metadata.
pub const ABI_FEATURE_AUDIT_METADATA: u64 = 1 << 5;

/// All feature bits known by this draft ABI.
pub const ABI_KNOWN_FEATURES: u64 = ABI_FEATURE_SYSCALL_TABLE
    | ABI_FEATURE_TRACE_CONTEXT
    | ABI_FEATURE_CAPABILITY_HANDLES
    | ABI_FEATURE_USER_BUFFERS
    | ABI_FEATURE_INFERENCE_BUDGETS
    | ABI_FEATURE_AUDIT_METADATA;

/// Current feature bitmap.
pub const ALANI_ABI_FEATURES: u64 = ABI_KNOWN_FEATURES;

/// Current draft ABI version exposed by `sys_info`.
pub const ALANI_ABI_VERSION: AbiVersion = AbiVersion {
    major: ALANI_ABI_MAJOR,
    minor: ALANI_ABI_MINOR,
    patch: ALANI_ABI_PATCH,
    flags: 0,
};

/// Default maximum user buffer size used by safe wrapper validation.
pub const DEFAULT_MAX_USER_BUFFER_LEN: u64 = 16 * 1024 * 1024;

/// Buffer may be read by the kernel.
pub const USER_BUFFER_READ: u32 = 1 << 0;
/// Buffer may be written by the kernel.
pub const USER_BUFFER_WRITE: u32 = 1 << 1;
/// Buffer may be pinned by the kernel.
pub const USER_BUFFER_PINNABLE: u32 = 1 << 2;
/// Known user-buffer flag bits.
pub const USER_BUFFER_KNOWN_FLAGS: u32 =
    USER_BUFFER_READ | USER_BUFFER_WRITE | USER_BUFFER_PINNABLE;

/// Trace context is sampled.
pub const TRACE_FLAG_SAMPLED: u32 = 1 << 0;
/// Trace context is debug-visible.
pub const TRACE_FLAG_DEBUG: u32 = 1 << 1;
/// Known trace context flag bits.
pub const TRACE_KNOWN_FLAGS: u32 = TRACE_FLAG_SAMPLED | TRACE_FLAG_DEBUG;

/// Inference should be deterministic when possible.
pub const INFERENCE_FLAG_DETERMINISTIC: u32 = 1 << 0;
/// Inference may use cached context.
pub const INFERENCE_FLAG_CACHE_ALLOWED: u32 = 1 << 1;
/// Known inference budget flag bits.
pub const INFERENCE_KNOWN_FLAGS: u32 = INFERENCE_FLAG_DETERMINISTIC | INFERENCE_FLAG_CACHE_ALLOWED;

/// Syscall may run during early boot.
pub const SYSCALL_CONTEXT_EARLY_BOOT: u32 = 1 << 0;
/// Syscall may run during normal task context.
pub const SYSCALL_CONTEXT_TASK: u32 = 1 << 1;
/// Syscall may run from interrupt context.
pub const SYSCALL_CONTEXT_INTERRUPT: u32 = 1 << 2;
/// Known syscall execution context bits.
pub const SYSCALL_CONTEXT_KNOWN_FLAGS: u32 =
    SYSCALL_CONTEXT_EARLY_BOOT | SYSCALL_CONTEXT_TASK | SYSCALL_CONTEXT_INTERRUPT;

/// Permission to spawn child tasks.
pub const CAP_TASK_SPAWN: u64 = 1 << 0;
/// Permission to manage task lifecycle.
pub const CAP_TASK_MANAGE: u64 = 1 << 1;
/// Permission to map or unmap memory.
pub const CAP_MEMORY_MAP: u64 = 1 << 2;
/// Permission to share or seal memory handles.
pub const CAP_MEMORY_SHARE: u64 = 1 << 3;
/// Permission to list devices.
pub const CAP_DEVICE_LIST: u64 = 1 << 4;
/// Permission to open devices.
pub const CAP_DEVICE_OPEN: u64 = 1 << 5;
/// Permission to call devices.
pub const CAP_DEVICE_CALL: u64 = 1 << 6;
/// Permission to invoke cognition inference.
pub const CAP_COGNITION_INFER: u64 = 1 << 7;
/// Permission to write cognition memory.
pub const CAP_COGNITION_MEMORY_WRITE: u64 = 1 << 8;
/// Permission to derive or revoke capability handles.
pub const CAP_CAPABILITY_ADMIN: u64 = 1 << 9;
/// Permission to request attestation material.
pub const CAP_ATTEST: u64 = 1 << 10;
/// Permission to request random bytes.
pub const CAP_RANDOM: u64 = 1 << 11;
/// Permission to append audit records.
pub const CAP_AUDIT_APPEND: u64 = 1 << 12;
/// Permission to query audit records.
pub const CAP_AUDIT_QUERY: u64 = 1 << 13;
/// Permission to verify audit evidence.
pub const CAP_AUDIT_VERIFY: u64 = 1 << 14;
/// Permission to emit trace context updates.
pub const CAP_TRACE_CONTEXT: u64 = 1 << 15;

/// All capability bits known by this draft ABI.
pub const KNOWN_CAPABILITY_RIGHTS: u64 = CAP_TASK_SPAWN
    | CAP_TASK_MANAGE
    | CAP_MEMORY_MAP
    | CAP_MEMORY_SHARE
    | CAP_DEVICE_LIST
    | CAP_DEVICE_OPEN
    | CAP_DEVICE_CALL
    | CAP_COGNITION_INFER
    | CAP_COGNITION_MEMORY_WRITE
    | CAP_CAPABILITY_ADMIN
    | CAP_ATTEST
    | CAP_RANDOM
    | CAP_AUDIT_APPEND
    | CAP_AUDIT_QUERY
    | CAP_AUDIT_VERIFY
    | CAP_TRACE_CONTEXT;

/// Number of syscalls in the canonical public table.
pub const SYSCALL_TABLE_LEN: usize = 30;

/// Syscall table version independent of crate version.
pub const SYSCALL_TABLE_VERSION: AbiVersion = AbiVersion {
    major: 0,
    minor: 1,
    patch: 0,
    flags: 0,
};

/// ABI version structure used for compatibility negotiation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiVersion {
    /// Major version. Incompatible changes require a bump.
    pub major: u16,
    /// Minor version. Compatible additions require a bump.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
    /// Reserved version flags. Must be zero for this draft ABI.
    pub flags: u16,
}

impl AbiVersion {
    /// Creates an ABI version value.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
            flags: 0,
        }
    }

    /// Encodes the version in a register-friendly integer.
    pub const fn packed(self) -> u64 {
        ((self.major as u64) << 48)
            | ((self.minor as u64) << 32)
            | ((self.patch as u64) << 16)
            | self.flags as u64
    }

    /// Decodes a packed ABI version.
    pub const fn from_packed(value: u64) -> Self {
        Self {
            major: (value >> 48) as u16,
            minor: (value >> 32) as u16,
            patch: (value >> 16) as u16,
            flags: value as u16,
        }
    }

    /// Validates reserved fields.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.flags == 0 {
            Ok(())
        } else {
            Err(AlaniError::ReservedBits)
        }
    }

    /// Returns `true` when `self` can consume structures from `other`.
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

/// Generic ABI structure header for extensible records.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiHeader {
    /// Structure size in bytes.
    pub size: u32,
    /// Structure flags. Unknown bits are rejected by structure-specific helpers.
    pub flags: u32,
    /// ABI version used by this structure.
    pub version: AbiVersion,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u64,
}

impl AbiHeader {
    /// Creates a structure header.
    pub const fn new(size: u32, flags: u32, version: AbiVersion) -> Self {
        Self {
            size,
            flags,
            version,
            reserved: 0,
        }
    }

    /// Validates size, version, reserved fields, and known flags.
    pub const fn validate(self, min_size: u32, known_flags: u32) -> AlaniResult<()> {
        if self.size < min_size {
            return Err(AlaniError::InvalidVersion);
        }
        if self.reserved != 0 || self.flags & !known_flags != 0 {
            return Err(AlaniError::ReservedBits);
        }
        self.version.validate()
    }
}

/// Feature set returned by compatibility negotiation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiFeatureSet(pub u64);

impl AbiFeatureSet {
    /// Empty feature set.
    pub const EMPTY: Self = Self(0);
    /// All known features enabled.
    pub const ALL: Self = Self(ABI_KNOWN_FEATURES);

    /// Creates a feature set from raw bits.
    pub const fn from_bits(bits: u64) -> AlaniResult<Self> {
        if bits & !ABI_KNOWN_FEATURES != 0 {
            Err(AlaniError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw feature bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all requested features are present.
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
}

/// Stable status values returned by kernel syscalls.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlaniStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// The caller provided malformed or out-of-range input.
    InvalidArgument = 1,
    /// The caller lacks authority for the requested operation.
    PermissionDenied = 2,
    /// The requested object does not exist.
    NotFound = 3,
    /// The subsystem is temporarily unable to make progress.
    Busy = 4,
    /// A declared deadline or budget was exceeded.
    DeadlineExceeded = 5,
    /// A kernel invariant failed or an internal subsystem fault occurred.
    Internal = 0xffff_ffff,
}

impl AlaniStatus {
    /// Converts a raw status code to a known status.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidArgument),
            2 => Some(Self::PermissionDenied),
            3 => Some(Self::NotFound),
            4 => Some(Self::Busy),
            5 => Some(Self::DeadlineExceeded),
            0xffff_ffff => Some(Self::Internal),
            _ => None,
        }
    }

    /// Returns the raw ABI status value.
    pub const fn raw(self) -> u32 {
        self as u32
    }

    /// Returns `true` when the status represents success.
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Stable status label used by tests, traces, and generated tables.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidArgument => "invalid_argument",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::Busy => "busy",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Internal => "internal",
        }
    }
}

/// User buffer descriptor passed through syscall arguments.
///
/// The pointer is an integer because Rust references and owned containers are
/// not stable ABI fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserBuffer {
    /// Userspace virtual address.
    pub ptr: u64,
    /// Buffer length in bytes.
    pub len: u64,
    /// Direction and pinning flags.
    pub flags: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl UserBuffer {
    /// Creates a descriptor from raw fields.
    pub const fn new(ptr: u64, len: u64, flags: u32) -> Self {
        Self {
            ptr,
            len,
            flags,
            reserved: 0,
        }
    }

    /// Creates a kernel-readable buffer from a byte slice.
    pub fn read_only(bytes: &[u8]) -> AlaniResult<Self> {
        Self::from_parts(
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            USER_BUFFER_READ,
        )
    }

    /// Creates a kernel-writable buffer from a mutable byte slice.
    pub fn write_only(bytes: &mut [u8]) -> AlaniResult<Self> {
        Self::from_parts(
            bytes.as_mut_ptr() as usize as u64,
            bytes.len() as u64,
            USER_BUFFER_WRITE,
        )
    }

    /// Creates a read/write buffer from a mutable byte slice.
    pub fn read_write(bytes: &mut [u8]) -> AlaniResult<Self> {
        Self::from_parts(
            bytes.as_mut_ptr() as usize as u64,
            bytes.len() as u64,
            USER_BUFFER_READ | USER_BUFFER_WRITE,
        )
    }

    /// Creates and validates a descriptor from raw parts.
    pub const fn from_parts(ptr: u64, len: u64, flags: u32) -> AlaniResult<Self> {
        let buffer = Self::new(ptr, len, flags);
        match buffer.validate() {
            Ok(()) => Ok(buffer),
            Err(error) => Err(error),
        }
    }

    /// Validates reserved fields, flags, null pointers, direction, and length ceiling.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved != 0 || self.flags & !USER_BUFFER_KNOWN_FLAGS != 0 {
            return Err(AlaniError::ReservedBits);
        }
        if self.flags & (USER_BUFFER_READ | USER_BUFFER_WRITE) == 0 {
            return Err(AlaniError::InvalidBuffer);
        }
        if self.ptr == 0 || self.len == 0 {
            return Err(AlaniError::InvalidBuffer);
        }
        if self.len > DEFAULT_MAX_USER_BUFFER_LEN {
            return Err(AlaniError::BufferTooLarge);
        }
        match self.checked_end() {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Returns the exclusive end address after checking for overflow.
    pub const fn checked_end(self) -> AlaniResult<u64> {
        match self.ptr.checked_add(self.len) {
            Some(end) => Ok(end),
            None => Err(AlaniError::InvalidBuffer),
        }
    }

    /// Validates that the user pointer is aligned to `alignment`.
    pub const fn validate_alignment(self, alignment: u64) -> AlaniResult<()> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(AlaniError::InvalidArgument);
        }
        match self.validate() {
            Ok(()) => {
                if self.ptr & (alignment - 1) == 0 {
                    Ok(())
                } else {
                    Err(AlaniError::InvalidBuffer)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Returns `true` when the buffer declares kernel-read access.
    pub const fn is_readable(self) -> bool {
        self.flags & USER_BUFFER_READ != 0
    }

    /// Returns `true` when the buffer declares kernel-write access.
    pub const fn is_writable(self) -> bool {
        self.flags & USER_BUFFER_WRITE != 0
    }

    /// Returns `true` when the buffer may be pinned by the kernel.
    pub const fn is_pinnable(self) -> bool {
        self.flags & USER_BUFFER_PINNABLE != 0
    }

    /// Packs the pointer/length pair into two syscall arguments.
    pub const fn ptr_len_args(self) -> [u64; 2] {
        [self.ptr, self.len]
    }
}

/// Generic kernel object handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Handle(pub u64);

impl Handle {
    /// Invalid handle value.
    pub const INVALID: Self = Self(0);

    /// Creates a handle from a raw value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw handle value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns `true` when the handle is nonzero.
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }

    /// Validates the handle.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(AlaniError::InvalidHandle)
        }
    }
}

/// Task handle returned by task syscalls.
pub type TaskHandle = Handle;
/// Device handle returned by device syscalls.
pub type DeviceHandle = Handle;
/// Model handle returned by model syscalls.
pub type ModelHandle = Handle;
/// Shared-memory handle returned by memory syscalls.
pub type SharedMemoryHandle = Handle;
/// Intent handle reserved for future cognition flows.
pub type IntentHandle = Handle;
/// Audit handle reserved for audit query flows.
pub type AuditHandle = Handle;

/// Kernel object kind encoded in capability provenance and diagnostics.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    /// No object kind.
    None = 0,
    /// Task object.
    Task = 1,
    /// Memory object.
    Memory = 2,
    /// Device object.
    Device = 3,
    /// Cognitive model object.
    Model = 4,
    /// Capability object.
    Capability = 5,
    /// Audit object.
    Audit = 6,
}

impl ObjectKind {
    /// Converts a raw value to a known object kind.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Task),
            2 => Some(Self::Memory),
            3 => Some(Self::Device),
            4 => Some(Self::Model),
            5 => Some(Self::Capability),
            6 => Some(Self::Audit),
            _ => None,
        }
    }
}

/// Capability rights bitset.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityRights(pub u64);

impl CapabilityRights {
    /// Empty rights set.
    pub const EMPTY: Self = Self(0);
    /// All known rights.
    pub const ALL: Self = Self(KNOWN_CAPABILITY_RIGHTS);

    /// Creates a rights set from raw bits.
    pub const fn from_bits(bits: u64) -> AlaniResult<Self> {
        if bits & !KNOWN_CAPABILITY_RIGHTS != 0 {
            Err(AlaniError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw rights bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all required rights are present.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Returns `true` when no rights are present.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the union of two rights sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Validates that no reserved rights bits are present.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.0 & !KNOWN_CAPABILITY_RIGHTS != 0 {
            Err(AlaniError::ReservedBits)
        } else {
            Ok(())
        }
    }
}

/// Capability handle represented by the kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityHandle {
    /// Kernel-assigned handle identifier. Zero is invalid.
    pub id: u64,
    /// Rights bitmask attached to the handle.
    pub rights: u64,
    /// Owning task identifier.
    pub owner_task: u64,
    /// Handle generation to prevent stale reuse.
    pub generation: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl CapabilityHandle {
    /// Invalid zero capability handle.
    pub const INVALID: Self = Self {
        id: 0,
        rights: 0,
        owner_task: 0,
        generation: 0,
        reserved: 0,
    };

    /// Creates a capability handle.
    pub const fn new(id: u64, rights: CapabilityRights, owner_task: u64, generation: u32) -> Self {
        Self {
            id,
            rights: rights.bits(),
            owner_task,
            generation,
            reserved: 0,
        }
    }

    /// Returns `true` when identity fields are nonzero.
    pub const fn is_valid(self) -> bool {
        self.id != 0 && self.owner_task != 0 && self.generation != 0
    }

    /// Returns the rights set if no unknown bits are present.
    pub const fn rights(self) -> AlaniResult<CapabilityRights> {
        CapabilityRights::from_bits(self.rights)
    }

    /// Validates nonzero identity, known rights, and reserved fields.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved != 0 {
            return Err(AlaniError::ReservedBits);
        }
        if !self.is_valid() {
            return Err(AlaniError::InvalidHandle);
        }
        match self.rights() {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Checks that the handle contains all required rights.
    pub const fn require(self, required: CapabilityRights) -> AlaniResult<()> {
        match self.validate() {
            Ok(()) => match self.rights() {
                Ok(rights) => {
                    if rights.contains(required) {
                        Ok(())
                    } else {
                        Err(AlaniError::MissingCapability)
                    }
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }
}

/// Typed handle descriptor used by table queries and diagnostics.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectHandle {
    /// Generic handle value.
    pub handle: Handle,
    /// Object kind.
    pub kind: ObjectKind,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl ObjectHandle {
    /// Creates a typed object handle.
    pub const fn new(handle: Handle, kind: ObjectKind) -> Self {
        Self {
            handle,
            kind,
            reserved: 0,
        }
    }

    /// Validates handle, object kind, and reserved fields.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved != 0 || matches!(self.kind, ObjectKind::None) {
            return Err(AlaniError::ReservedBits);
        }
        self.handle.validate()
    }
}

/// Cross-component trace context propagated through syscalls.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// Stable trace identifier.
    pub trace_id: u64,
    /// Current span identifier.
    pub span_id: u64,
    /// Parent span identifier, or zero when absent.
    pub parent_span_id: u64,
    /// Trace flags.
    pub flags: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl TraceContext {
    /// Empty trace context.
    pub const EMPTY: Self = Self {
        trace_id: 0,
        span_id: 0,
        parent_span_id: 0,
        flags: 0,
        reserved: 0,
    };

    /// Returns an empty trace context.
    pub const fn empty() -> Self {
        Self::EMPTY
    }

    /// Creates a context with no parent.
    pub const fn root(trace_id: u64, span_id: u64) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: 0,
            flags: TRACE_FLAG_SAMPLED,
            reserved: 0,
        }
    }

    /// Creates a child span context.
    pub const fn child(self, span_id: u64) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id,
            parent_span_id: self.span_id,
            flags: self.flags,
            reserved: 0,
        }
    }

    /// Returns `true` when a trace id and span id are present.
    pub const fn is_valid_context(self) -> bool {
        self.trace_id != 0 && self.span_id != 0
    }

    /// Returns `true` when this context requests sampling.
    pub const fn is_sampled(self) -> bool {
        self.flags & TRACE_FLAG_SAMPLED != 0
    }

    /// Validates reserved fields, known flags, and trace/span consistency.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved != 0 || self.flags & !TRACE_KNOWN_FLAGS != 0 {
            return Err(AlaniError::ReservedBits);
        }
        if (self.trace_id == 0) != (self.span_id == 0) {
            return Err(AlaniError::InvalidTrace);
        }
        Ok(())
    }
}

/// Budget descriptor carried by cognitive syscalls.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferenceBudget {
    /// Maximum output tokens. Zero means unspecified.
    pub max_tokens: u32,
    /// Maximum compute units. Zero means unspecified.
    pub max_compute_units: u32,
    /// Absolute deadline in monotonic nanoseconds, or zero when unset.
    pub deadline_ns: u64,
    /// Budget flags. Unknown bits are rejected by helpers.
    pub flags: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl InferenceBudget {
    /// Unbounded budget placeholder. Kernel policy may still deny it.
    pub const UNBOUNDED: Self = Self {
        max_tokens: 0,
        max_compute_units: 0,
        deadline_ns: 0,
        flags: 0,
        reserved: 0,
    };

    /// Creates a bounded budget.
    pub const fn bounded(max_tokens: u32, max_compute_units: u32, deadline_ns: u64) -> Self {
        Self {
            max_tokens,
            max_compute_units,
            deadline_ns,
            flags: 0,
            reserved: 0,
        }
    }

    /// Enables deterministic inference when a backend can honor it.
    pub const fn deterministic(mut self) -> Self {
        self.flags |= INFERENCE_FLAG_DETERMINISTIC;
        self
    }

    /// Allows cache use for inference context.
    pub const fn cache_allowed(mut self) -> Self {
        self.flags |= INFERENCE_FLAG_CACHE_ALLOWED;
        self
    }

    /// Returns `true` when at least one bound is set.
    pub const fn is_bounded(self) -> bool {
        self.max_tokens != 0 || self.max_compute_units != 0 || self.deadline_ns != 0
    }

    /// Validates reserved fields and known flags.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved != 0 || self.flags & !INFERENCE_KNOWN_FLAGS != 0 {
            Err(AlaniError::ReservedBits)
        } else {
            Ok(())
        }
    }
}

/// Options passed to `sys_task_spawn`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskSpawnOptions {
    /// Structure size in bytes.
    pub size: u32,
    /// Spawn flags. No nonzero flags are assigned in this draft.
    pub flags: u32,
    /// Scheduler priority hint.
    pub priority: u8,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved0: u8,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved1: u16,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved2: u32,
}

impl TaskSpawnOptions {
    /// Default options with normal priority.
    pub const DEFAULT: Self = Self {
        size: size_of::<Self>() as u32,
        flags: 0,
        priority: 0,
        reserved0: 0,
        reserved1: 0,
        reserved2: 0,
    };

    /// Creates options with a priority hint.
    pub const fn priority(priority: u8) -> Self {
        Self {
            priority,
            ..Self::DEFAULT
        }
    }

    /// Validates size, flags, and reserved fields.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.size < size_of::<Self>() as u32 {
            return Err(AlaniError::InvalidVersion);
        }
        if self.flags != 0 || self.reserved0 != 0 || self.reserved1 != 0 || self.reserved2 != 0 {
            return Err(AlaniError::ReservedBits);
        }
        Ok(())
    }
}

/// Syscall groups defined by the syscall interface.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallGroup {
    /// System calls.
    System = 0x0000,
    /// Task lifecycle calls.
    Task = 0x0100,
    /// Memory calls.
    Memory = 0x0200,
    /// Device calls.
    Device = 0x0300,
    /// Cognitive model and memory calls.
    Cognition = 0x0400,
    /// Security and capability calls.
    Security = 0x0500,
    /// Audit calls.
    Audit = 0x0600,
    /// Debug and tracing calls.
    Debug = 0x0700,
}

/// Stable syscall numbers for MVK and near-term expansion.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallNumber {
    /// Query ABI and syscall table information.
    SysInfo = 0x0000,
    /// Cooperatively yield the current task.
    SysYield = 0x0001,
    /// Exit the current task.
    SysExit = 0x0002,
    /// Query monotonic time.
    SysTime = 0x0003,
    /// Create or update trace context.
    SysTraceContext = 0x0004,
    /// Spawn a task from a manifest.
    SysTaskSpawn = 0x0100,
    /// Join a task.
    SysTaskJoin = 0x0101,
    /// Cancel a task.
    SysTaskCancel = 0x0102,
    /// Query task status.
    SysTaskStatus = 0x0103,
    /// Map memory.
    SysMemMap = 0x0200,
    /// Unmap memory.
    SysMemUnmap = 0x0201,
    /// Query memory.
    SysMemQuery = 0x0202,
    /// Share memory.
    SysMemShare = 0x0203,
    /// Seal shared memory.
    SysMemSeal = 0x0204,
    /// List devices.
    SysDeviceList = 0x0300,
    /// Open device.
    SysDeviceOpen = 0x0301,
    /// Call device.
    SysDeviceCall = 0x0302,
    /// Close device.
    SysDeviceClose = 0x0303,
    /// Invoke inference.
    SysInfer = 0x0400,
    /// List models.
    SysModelList = 0x0401,
    /// Open model.
    SysModelOpen = 0x0402,
    /// Query cognitive memory.
    SysMemoryQuery = 0x0403,
    /// Put cognitive memory.
    SysMemoryPut = 0x0404,
    /// Derive capability.
    SysCapDerive = 0x0500,
    /// Revoke capability.
    SysCapRevoke = 0x0501,
    /// Query attestation.
    SysAttest = 0x0502,
    /// Request random bytes.
    SysRandom = 0x0503,
    /// Append audit record.
    SysAuditAppend = 0x0600,
    /// Query audit records.
    SysAuditQuery = 0x0601,
    /// Verify audit range.
    SysAuditVerify = 0x0602,
}

impl SyscallNumber {
    /// Converts a raw number to a known syscall.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0x0000 => Some(Self::SysInfo),
            0x0001 => Some(Self::SysYield),
            0x0002 => Some(Self::SysExit),
            0x0003 => Some(Self::SysTime),
            0x0004 => Some(Self::SysTraceContext),
            0x0100 => Some(Self::SysTaskSpawn),
            0x0101 => Some(Self::SysTaskJoin),
            0x0102 => Some(Self::SysTaskCancel),
            0x0103 => Some(Self::SysTaskStatus),
            0x0200 => Some(Self::SysMemMap),
            0x0201 => Some(Self::SysMemUnmap),
            0x0202 => Some(Self::SysMemQuery),
            0x0203 => Some(Self::SysMemShare),
            0x0204 => Some(Self::SysMemSeal),
            0x0300 => Some(Self::SysDeviceList),
            0x0301 => Some(Self::SysDeviceOpen),
            0x0302 => Some(Self::SysDeviceCall),
            0x0303 => Some(Self::SysDeviceClose),
            0x0400 => Some(Self::SysInfer),
            0x0401 => Some(Self::SysModelList),
            0x0402 => Some(Self::SysModelOpen),
            0x0403 => Some(Self::SysMemoryQuery),
            0x0404 => Some(Self::SysMemoryPut),
            0x0500 => Some(Self::SysCapDerive),
            0x0501 => Some(Self::SysCapRevoke),
            0x0502 => Some(Self::SysAttest),
            0x0503 => Some(Self::SysRandom),
            0x0600 => Some(Self::SysAuditAppend),
            0x0601 => Some(Self::SysAuditQuery),
            0x0602 => Some(Self::SysAuditVerify),
            _ => None,
        }
    }

    /// Returns the raw syscall number.
    pub const fn raw(self) -> u32 {
        self as u32
    }

    /// Stable syscall name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::SysInfo => "sys_info",
            Self::SysYield => "sys_yield",
            Self::SysExit => "sys_exit",
            Self::SysTime => "sys_time",
            Self::SysTraceContext => "sys_trace_context",
            Self::SysTaskSpawn => "sys_task_spawn",
            Self::SysTaskJoin => "sys_task_join",
            Self::SysTaskCancel => "sys_task_cancel",
            Self::SysTaskStatus => "sys_task_status",
            Self::SysMemMap => "sys_mem_map",
            Self::SysMemUnmap => "sys_mem_unmap",
            Self::SysMemQuery => "sys_mem_query",
            Self::SysMemShare => "sys_mem_share",
            Self::SysMemSeal => "sys_mem_seal",
            Self::SysDeviceList => "sys_device_list",
            Self::SysDeviceOpen => "sys_device_open",
            Self::SysDeviceCall => "sys_device_call",
            Self::SysDeviceClose => "sys_device_close",
            Self::SysInfer => "sys_infer",
            Self::SysModelList => "sys_model_list",
            Self::SysModelOpen => "sys_model_open",
            Self::SysMemoryQuery => "sys_memory_query",
            Self::SysMemoryPut => "sys_memory_put",
            Self::SysCapDerive => "sys_cap_derive",
            Self::SysCapRevoke => "sys_cap_revoke",
            Self::SysAttest => "sys_attest",
            Self::SysRandom => "sys_random",
            Self::SysAuditAppend => "sys_audit_append",
            Self::SysAuditQuery => "sys_audit_query",
            Self::SysAuditVerify => "sys_audit_verify",
        }
    }

    /// Syscall group.
    pub const fn group(self) -> SyscallGroup {
        match (self as u32) & 0xff00 {
            0x0100 => SyscallGroup::Task,
            0x0200 => SyscallGroup::Memory,
            0x0300 => SyscallGroup::Device,
            0x0400 => SyscallGroup::Cognition,
            0x0500 => SyscallGroup::Security,
            0x0600 => SyscallGroup::Audit,
            0x0700 => SyscallGroup::Debug,
            _ => SyscallGroup::System,
        }
    }
}

/// Execution context for syscall validation.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionContext {
    /// Kernel initialization context.
    EarlyBoot = 0,
    /// Normal task context.
    Task = 1,
    /// Interrupt context.
    Interrupt = 2,
}

/// Audit event metadata for syscall descriptors.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditEvent {
    /// No audit event required.
    None = 0,
    /// System information queried.
    SystemInfo = 1,
    /// Task lifecycle changed.
    TaskLifecycle = 2,
    /// Memory mapping or sharing changed.
    Memory = 3,
    /// Device authority was used.
    Device = 4,
    /// Cognition authority was used.
    Cognition = 5,
    /// Capability state changed.
    Capability = 6,
    /// Security evidence was requested.
    Security = 7,
    /// Audit evidence changed or was verified.
    Audit = 8,
}

/// Syscall argument kind for descriptor metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallArgKind {
    /// No argument.
    None = 0,
    /// Plain integer value.
    Value = 1,
    /// Kernel handle.
    Handle = 2,
    /// User pointer address.
    UserPtr = 3,
    /// User buffer length.
    Length = 4,
    /// Flags bitmask.
    Flags = 5,
    /// Pointer to an ABI structure.
    StructPtr = 6,
}

/// Architecture-neutral syscall register frame.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallFrame {
    /// Syscall number.
    pub number: u64,
    /// Up to six integer arguments.
    pub args: [u64; 6],
    /// Propagated trace context.
    pub trace: TraceContext,
}

impl SyscallFrame {
    /// Creates a traced syscall frame.
    pub const fn new(number: SyscallNumber, args: [u64; 6], trace: TraceContext) -> Self {
        Self {
            number: number as u64,
            args,
            trace,
        }
    }

    /// Creates a traced syscall frame.
    pub const fn traced(number: SyscallNumber, args: [u64; 6], trace: TraceContext) -> Self {
        Self::new(number, args, trace)
    }

    /// Creates an untraced syscall frame.
    pub const fn untraced(number: SyscallNumber, args: [u64; 6]) -> Self {
        Self::new(number, args, TraceContext::EMPTY)
    }

    /// Creates a frame from a raw syscall number.
    pub const fn raw(number: u64, args: [u64; 6]) -> Self {
        Self {
            number,
            args,
            trace: TraceContext::EMPTY,
        }
    }

    /// Returns the known syscall number or an error.
    pub const fn syscall_number(self) -> AlaniResult<SyscallNumber> {
        match SyscallNumber::from_raw(self.number) {
            Some(number) => Ok(number),
            None => Err(AlaniError::UnknownSyscall),
        }
    }

    /// Validates the frame number and trace context.
    pub const fn validate(self) -> AlaniResult<()> {
        match self.syscall_number() {
            Ok(_) => self.trace.validate(),
            Err(error) => Err(error),
        }
    }

    /// Returns the canonical descriptor for this frame.
    pub fn descriptor(self) -> AlaniResult<&'static SyscallDescriptor> {
        match self.syscall_number() {
            Ok(number) => descriptor(number).ok_or(AlaniError::UnknownSyscall),
            Err(error) => Err(error),
        }
    }

    /// Validates syscall number, trace context, and execution context.
    pub fn validate_for_context(self, context: ExecutionContext) -> AlaniResult<()> {
        self.validate()?;
        let descriptor = self.descriptor()?;
        if descriptor.allows_context(context) {
            Ok(())
        } else {
            Err(AlaniError::InvalidContext)
        }
    }

    /// Validates that `capability` has the rights required by this syscall.
    pub fn authorize(self, capability: CapabilityHandle) -> AlaniResult<()> {
        let descriptor = self.descriptor()?;
        if descriptor.required_rights.is_empty() {
            Ok(())
        } else {
            capability.require(descriptor.required_rights)
        }
    }

    /// Validates frame, execution context, and optional capability in one step.
    pub fn validate_dispatch(
        self,
        context: ExecutionContext,
        capability: Option<CapabilityHandle>,
    ) -> AlaniResult<&'static SyscallDescriptor> {
        self.validate_for_context(context)?;
        let descriptor = self.descriptor()?;
        if descriptor.required_rights.is_empty() {
            return Ok(descriptor);
        }
        match capability {
            Some(capability) => capability.require(descriptor.required_rights)?,
            None => return Err(AlaniError::MissingCapability),
        }
        Ok(descriptor)
    }
}

/// Syscall return registers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallReturn {
    /// Stable status.
    pub status: AlaniStatus,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
    /// Primary value or handle.
    pub value: u64,
    /// Secondary value, usually length or count.
    pub detail: u64,
}

impl SyscallReturn {
    /// Successful return.
    pub const fn ok(value: u64, detail: u64) -> Self {
        Self {
            status: AlaniStatus::Ok,
            reserved: 0,
            value,
            detail,
        }
    }

    /// Error return.
    pub const fn error(status: AlaniStatus) -> Self {
        Self {
            status,
            reserved: 0,
            value: 0,
            detail: 0,
        }
    }

    /// Validates reserved fields and status values.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved != 0 {
            return Err(AlaniError::ReservedBits);
        }
        if self.status.is_ok() {
            Ok(())
        } else {
            Err(AlaniError::from_status(self.status))
        }
    }

    /// Converts the return status into a Rust result.
    pub const fn into_result(self) -> AlaniResult<Self> {
        match self.validate() {
            Ok(()) => Ok(self),
            Err(error) => Err(error),
        }
    }
}

/// Information returned by `sys_info`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SysInfo {
    /// Structure size in bytes.
    pub size: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
    /// ABI version.
    pub abi_version: AbiVersion,
    /// Syscall table version.
    pub table_version: AbiVersion,
    /// Number of syscalls in the public table.
    pub syscall_count: u32,
    /// Maximum user buffer length accepted by the kernel.
    pub max_user_buffer_len: u64,
    /// Feature bitmap.
    pub features: u64,
}

impl SysInfo {
    /// Current system information payload.
    pub const CURRENT: Self = Self {
        size: size_of::<Self>() as u32,
        reserved: 0,
        abi_version: ALANI_ABI_VERSION,
        table_version: SYSCALL_TABLE_VERSION,
        syscall_count: SYSCALL_TABLE_LEN as u32,
        max_user_buffer_len: DEFAULT_MAX_USER_BUFFER_LEN,
        features: ALANI_ABI_FEATURES,
    };

    /// Creates a `SysInfo` from the compact return used by host-mode tests.
    pub const fn from_return(ret: SyscallReturn) -> Self {
        Self {
            size: size_of::<Self>() as u32,
            reserved: 0,
            abi_version: AbiVersion::from_packed(ret.value),
            table_version: AbiVersion::from_packed(ret.value),
            syscall_count: SYSCALL_TABLE_LEN as u32,
            max_user_buffer_len: ret.detail,
            features: ALANI_ABI_FEATURES,
        }
    }

    /// Validates size, reserved fields, versions, and known feature bits.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.size < size_of::<Self>() as u32 {
            return Err(AlaniError::InvalidVersion);
        }
        if self.reserved != 0 {
            return Err(AlaniError::ReservedBits);
        }
        if self.features & !ALANI_ABI_FEATURES != 0 {
            return Err(AlaniError::ReservedBits);
        }
        if self.syscall_count < SYSCALL_TABLE_LEN as u32 || self.max_user_buffer_len == 0 {
            return Err(AlaniError::InvalidVersion);
        }
        match self.abi_version.validate() {
            Ok(()) => self.table_version.validate(),
            Err(error) => Err(error),
        }
    }
}

/// Task state values returned by `sys_task_status`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    /// Task is new.
    New = 0,
    /// Task is ready.
    Ready = 1,
    /// Task is running.
    Running = 2,
    /// Task is blocked.
    Blocked = 3,
    /// Task is sleeping.
    Sleeping = 4,
    /// Task is suspended.
    Suspended = 5,
    /// Task is exiting.
    Exiting = 6,
    /// Task is zombie.
    Zombie = 7,
}

impl TaskState {
    /// Converts a raw task state to a known value.
    pub const fn from_raw(raw: u64) -> AlaniResult<Self> {
        match raw {
            0 => Ok(Self::New),
            1 => Ok(Self::Ready),
            2 => Ok(Self::Running),
            3 => Ok(Self::Blocked),
            4 => Ok(Self::Sleeping),
            5 => Ok(Self::Suspended),
            6 => Ok(Self::Exiting),
            7 => Ok(Self::Zombie),
            _ => Err(AlaniError::InvalidValue),
        }
    }
}

/// Memory mapping flags for `sys_mem_map`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryMapFlags {
    bits: u64,
}

impl MemoryMapFlags {
    /// Readable mapping.
    pub const READ: Self = Self { bits: 1 << 0 };
    /// Writable mapping.
    pub const WRITE: Self = Self { bits: 1 << 1 };
    /// Executable mapping.
    pub const EXECUTE: Self = Self { bits: 1 << 2 };
    /// Shared mapping.
    pub const SHARED: Self = Self { bits: 1 << 3 };

    /// Empty flags.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Returns raw bits.
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Constructs flags from raw bits after rejecting unknown values.
    pub const fn from_bits(bits: u64) -> AlaniResult<Self> {
        let flags = Self { bits };
        match flags.validate() {
            Ok(()) => Ok(flags),
            Err(error) => Err(error),
        }
    }

    /// Returns `true` when all requested flags are present.
    pub const fn contains(self, requested: Self) -> bool {
        self.bits & requested.bits == requested.bits
    }

    /// Returns a union of two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Validates unknown bits.
    pub const fn validate(self) -> AlaniResult<()> {
        let known = Self::READ.bits | Self::WRITE.bits | Self::EXECUTE.bits | Self::SHARED.bits;
        if self.bits & !known == 0 {
            Ok(())
        } else {
            Err(AlaniError::ReservedBits)
        }
    }
}

/// Static descriptor for one syscall table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallDescriptor {
    /// Stable syscall number.
    pub number: SyscallNumber,
    /// Stable syscall name.
    pub name: &'static str,
    /// Required capability rights, or zero when unauthenticated.
    pub required_rights: CapabilityRights,
    /// Audit event emitted for authority-sensitive calls.
    pub audit_event: AuditEvent,
    /// Execution contexts where the syscall may run.
    pub context_flags: u32,
    /// Argument kind metadata.
    pub args: [SyscallArgKind; 6],
}

impl SyscallDescriptor {
    /// Returns `true` when this syscall requires a capability.
    pub const fn requires_capability(self) -> bool {
        !self.required_rights.is_empty()
    }

    /// Returns `true` when this syscall has audit-relevant metadata.
    pub const fn requires_audit(self) -> bool {
        !matches!(self.audit_event, AuditEvent::None)
    }

    /// Returns `true` when the descriptor allows the execution context.
    pub const fn allows_context(self, context: ExecutionContext) -> bool {
        let required = match context {
            ExecutionContext::EarlyBoot => SYSCALL_CONTEXT_EARLY_BOOT,
            ExecutionContext::Task => SYSCALL_CONTEXT_TASK,
            ExecutionContext::Interrupt => SYSCALL_CONTEXT_INTERRUPT,
        };
        self.context_flags & required != 0
    }

    /// Validates descriptor table metadata.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.context_flags & !SYSCALL_CONTEXT_KNOWN_FLAGS != 0 {
            return Err(AlaniError::ReservedBits);
        }
        if self.context_flags == 0 {
            return Err(AlaniError::InvalidContext);
        }
        if self.name.is_empty() {
            return Err(AlaniError::InvalidArgument);
        }
        if self.required_rights.validate().is_err() {
            return Err(AlaniError::ReservedBits);
        }
        Ok(())
    }
}

/// Returns a descriptor for the given syscall number.
pub fn descriptor(number: SyscallNumber) -> Option<&'static SyscallDescriptor> {
    SYSCALL_TABLE
        .iter()
        .find(|descriptor| descriptor.number == number)
}

/// Returns a descriptor for a raw syscall number.
pub fn descriptor_from_raw(raw: u64) -> Option<&'static SyscallDescriptor> {
    SyscallNumber::from_raw(raw).and_then(descriptor)
}

const NONE: SyscallArgKind = SyscallArgKind::None;
const VALUE: SyscallArgKind = SyscallArgKind::Value;
const HANDLE: SyscallArgKind = SyscallArgKind::Handle;
const USER_PTR: SyscallArgKind = SyscallArgKind::UserPtr;
const LENGTH: SyscallArgKind = SyscallArgKind::Length;
const FLAGS: SyscallArgKind = SyscallArgKind::Flags;
const STRUCT_PTR: SyscallArgKind = SyscallArgKind::StructPtr;
const TASK_CONTEXT: u32 = SYSCALL_CONTEXT_TASK;
const BOOT_TASK_CONTEXT: u32 = SYSCALL_CONTEXT_EARLY_BOOT | SYSCALL_CONTEXT_TASK;
const ANY_CONTEXT: u32 =
    SYSCALL_CONTEXT_EARLY_BOOT | SYSCALL_CONTEXT_TASK | SYSCALL_CONTEXT_INTERRUPT;

/// Canonical syscall descriptor table.
pub const SYSCALL_TABLE: [SyscallDescriptor; SYSCALL_TABLE_LEN] = [
    SyscallDescriptor {
        number: SyscallNumber::SysInfo,
        name: "sys_info",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::SystemInfo,
        context_flags: ANY_CONTEXT,
        args: [USER_PTR, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysYield,
        name: "sys_yield",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::None,
        context_flags: TASK_CONTEXT,
        args: [NONE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysExit,
        name: "sys_exit",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::TaskLifecycle,
        context_flags: TASK_CONTEXT,
        args: [VALUE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTime,
        name: "sys_time",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::None,
        context_flags: ANY_CONTEXT,
        args: [NONE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTraceContext,
        name: "sys_trace_context",
        required_rights: CapabilityRights(CAP_TRACE_CONTEXT),
        audit_event: AuditEvent::None,
        context_flags: ANY_CONTEXT,
        args: [STRUCT_PTR, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskSpawn,
        name: "sys_task_spawn",
        required_rights: CapabilityRights(CAP_TASK_SPAWN),
        audit_event: AuditEvent::TaskLifecycle,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, STRUCT_PTR, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskJoin,
        name: "sys_task_join",
        required_rights: CapabilityRights(CAP_TASK_MANAGE),
        audit_event: AuditEvent::TaskLifecycle,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskCancel,
        name: "sys_task_cancel",
        required_rights: CapabilityRights(CAP_TASK_MANAGE),
        audit_event: AuditEvent::TaskLifecycle,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskStatus,
        name: "sys_task_status",
        required_rights: CapabilityRights(CAP_TASK_MANAGE),
        audit_event: AuditEvent::None,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, USER_PTR, LENGTH, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemMap,
        name: "sys_mem_map",
        required_rights: CapabilityRights(CAP_MEMORY_MAP),
        audit_event: AuditEvent::Memory,
        context_flags: TASK_CONTEXT,
        args: [VALUE, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemUnmap,
        name: "sys_mem_unmap",
        required_rights: CapabilityRights(CAP_MEMORY_MAP),
        audit_event: AuditEvent::Memory,
        context_flags: TASK_CONTEXT,
        args: [VALUE, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemQuery,
        name: "sys_mem_query",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::None,
        context_flags: BOOT_TASK_CONTEXT,
        args: [USER_PTR, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemShare,
        name: "sys_mem_share",
        required_rights: CapabilityRights(CAP_MEMORY_SHARE),
        audit_event: AuditEvent::Memory,
        context_flags: TASK_CONTEXT,
        args: [VALUE, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemSeal,
        name: "sys_mem_seal",
        required_rights: CapabilityRights(CAP_MEMORY_SHARE),
        audit_event: AuditEvent::Memory,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceList,
        name: "sys_device_list",
        required_rights: CapabilityRights(CAP_DEVICE_LIST),
        audit_event: AuditEvent::None,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceOpen,
        name: "sys_device_open",
        required_rights: CapabilityRights(CAP_DEVICE_OPEN),
        audit_event: AuditEvent::Device,
        context_flags: TASK_CONTEXT,
        args: [VALUE, FLAGS, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceCall,
        name: "sys_device_call",
        required_rights: CapabilityRights(CAP_DEVICE_CALL),
        audit_event: AuditEvent::Device,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, VALUE, USER_PTR, LENGTH, USER_PTR, LENGTH],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceClose,
        name: "sys_device_close",
        required_rights: CapabilityRights(CAP_DEVICE_CALL),
        audit_event: AuditEvent::Device,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysInfer,
        name: "sys_infer",
        required_rights: CapabilityRights(CAP_COGNITION_INFER),
        audit_event: AuditEvent::Cognition,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, USER_PTR, LENGTH, VALUE, USER_PTR, LENGTH],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysModelList,
        name: "sys_model_list",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::None,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysModelOpen,
        name: "sys_model_open",
        required_rights: CapabilityRights(CAP_COGNITION_INFER),
        audit_event: AuditEvent::Cognition,
        context_flags: TASK_CONTEXT,
        args: [VALUE, FLAGS, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemoryQuery,
        name: "sys_memory_query",
        required_rights: CapabilityRights(CAP_COGNITION_INFER),
        audit_event: AuditEvent::Cognition,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, USER_PTR, LENGTH, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemoryPut,
        name: "sys_memory_put",
        required_rights: CapabilityRights(CAP_COGNITION_MEMORY_WRITE),
        audit_event: AuditEvent::Cognition,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysCapDerive,
        name: "sys_cap_derive",
        required_rights: CapabilityRights(CAP_CAPABILITY_ADMIN),
        audit_event: AuditEvent::Capability,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, VALUE, USER_PTR, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysCapRevoke,
        name: "sys_cap_revoke",
        required_rights: CapabilityRights(CAP_CAPABILITY_ADMIN),
        audit_event: AuditEvent::Capability,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAttest,
        name: "sys_attest",
        required_rights: CapabilityRights(CAP_ATTEST),
        audit_event: AuditEvent::Security,
        context_flags: BOOT_TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysRandom,
        name: "sys_random",
        required_rights: CapabilityRights(CAP_RANDOM),
        audit_event: AuditEvent::Security,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditAppend,
        name: "sys_audit_append",
        required_rights: CapabilityRights(CAP_AUDIT_APPEND),
        audit_event: AuditEvent::Audit,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditQuery,
        name: "sys_audit_query",
        required_rights: CapabilityRights(CAP_AUDIT_QUERY),
        audit_event: AuditEvent::Audit,
        context_flags: TASK_CONTEXT,
        args: [VALUE, VALUE, USER_PTR, LENGTH, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditVerify,
        name: "sys_audit_verify",
        required_rights: CapabilityRights(CAP_AUDIT_VERIFY),
        audit_event: AuditEvent::Audit,
        context_flags: TASK_CONTEXT,
        args: [VALUE, VALUE, USER_PTR, LENGTH, NONE, NONE],
    },
];
