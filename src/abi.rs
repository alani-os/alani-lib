//! ABI-safe data structures shared by userspace wrappers and kernel tests.
//!
//! This module mirrors the draft ABI while `alani-abi` stabilizes. Public
//! structures that can cross the kernel boundary use `#[repr(C)]`, fixed-width
//! integers, version fields, reserved fields, and explicit flag validation.

use crate::error::{AlaniError, AlaniResult};

/// Current draft ABI version exposed by `sys_info`.
pub const ALANI_ABI_VERSION: AbiVersion = AbiVersion {
    major: 0,
    minor: 1,
    patch: 0,
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
    /// Reserved feature flags.
    pub flags: u16,
}

impl AbiVersion {
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

    /// Returns `true` when the status represents success.
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
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
    pub fn from_parts(ptr: u64, len: u64, flags: u32) -> AlaniResult<Self> {
        let buffer = Self::new(ptr, len, flags);
        buffer.validate()?;
        Ok(buffer)
    }

    /// Validates reserved fields, flags, null pointers, and length ceiling.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved != 0 || self.flags & !USER_BUFFER_KNOWN_FLAGS != 0 {
            return Err(AlaniError::ReservedBits);
        }
        if self.ptr == 0 || self.len == 0 {
            return Err(AlaniError::InvalidBuffer);
        }
        if self.len > DEFAULT_MAX_USER_BUFFER_LEN {
            return Err(AlaniError::BufferTooLarge);
        }
        Ok(())
    }

    /// Returns `true` when the buffer declares kernel-read access.
    pub const fn is_readable(self) -> bool {
        self.flags & USER_BUFFER_READ != 0
    }

    /// Returns `true` when the buffer declares kernel-write access.
    pub const fn is_writable(self) -> bool {
        self.flags & USER_BUFFER_WRITE != 0
    }

    /// Packs the pointer/length pair into two syscall arguments.
    pub const fn ptr_len_args(self) -> [u64; 2] {
        [self.ptr, self.len]
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
}

impl CapabilityHandle {
    /// Invalid zero handle.
    pub const INVALID: Self = Self {
        id: 0,
        rights: 0,
        owner_task: 0,
        generation: 0,
    };

    /// Returns `true` when the handle can be passed to the kernel.
    pub const fn is_valid(self) -> bool {
        self.id != 0
    }
}

/// Generic kernel object handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Handle(pub u64);

impl Handle {
    /// Invalid handle value.
    pub const INVALID: Self = Self(0);

    /// Returns `true` when the handle is nonzero.
    pub const fn is_valid(self) -> bool {
        self.0 != 0
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

    /// Creates a context with no parent.
    pub const fn root(trace_id: u64, span_id: u64) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: 0,
            flags: 0,
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
    pub const fn is_sampled(self) -> bool {
        self.trace_id != 0 && self.span_id != 0
    }

    /// Validates reserved fields.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved == 0 {
            Ok(())
        } else {
            Err(AlaniError::ReservedBits)
        }
    }
}

/// Budget descriptor carried by cognitive syscalls.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferenceBudget {
    /// Maximum output tokens.
    pub max_tokens: u32,
    /// Maximum compute units.
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

    /// Returns `true` when at least one bound is set.
    pub const fn is_bounded(self) -> bool {
        self.max_tokens != 0 || self.max_compute_units != 0 || self.deadline_ns != 0
    }

    /// Validates reserved fields.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.reserved == 0 && self.flags == 0 {
            Ok(())
        } else {
            Err(AlaniError::ReservedBits)
        }
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
    /// Debug calls.
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
    /// List models.
    SysModelList = 0x0400,
    /// Open model.
    SysModelOpen = 0x0401,
    /// Invoke inference.
    SysInfer = 0x0402,
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
            0x0400 => Some(Self::SysModelList),
            0x0401 => Some(Self::SysModelOpen),
            0x0402 => Some(Self::SysInfer),
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
            Self::SysModelList => "sys_model_list",
            Self::SysModelOpen => "sys_model_open",
            Self::SysInfer => "sys_infer",
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

    /// Creates an untraced syscall frame.
    pub const fn untraced(number: SyscallNumber, args: [u64; 6]) -> Self {
        Self::new(number, args, TraceContext::EMPTY)
    }
}

/// Syscall return registers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallReturn {
    /// Stable status.
    pub status: AlaniStatus,
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
            value,
            detail,
        }
    }

    /// Error return.
    pub const fn error(status: AlaniStatus) -> Self {
        Self {
            status,
            value: 0,
            detail: 0,
        }
    }

    /// Converts the return status into a Rust result.
    pub const fn into_result(self) -> AlaniResult<Self> {
        if self.status.is_ok() {
            Ok(self)
        } else {
            Err(AlaniError::from_status(self.status))
        }
    }
}

/// Information returned by `sys_info`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SysInfo {
    /// ABI version.
    pub abi_version: AbiVersion,
    /// Syscall table version.
    pub table_version: AbiVersion,
    /// Maximum user buffer length accepted by the kernel.
    pub max_buffer_len: u64,
    /// Feature bitmap.
    pub features: u64,
}

impl SysInfo {
    /// Creates a `SysInfo` from the compact return used by host-mode tests.
    pub const fn from_return(ret: SyscallReturn) -> Self {
        Self {
            abi_version: AbiVersion::from_packed(ret.value),
            table_version: AbiVersion::from_packed(ret.value),
            max_buffer_len: ret.detail,
            features: 0,
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
