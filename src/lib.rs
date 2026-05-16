#![cfg_attr(not(feature = "std"), no_std)]

//! Shared safe wrappers, ABI types, result vocabulary, and trace helpers.
//!
//! `alani-lib` is the ergonomic layer used by userspace and services. It stays
//! dependency-free while `alani-abi` stabilizes, but its public API is shaped to
//! mirror the draft ABI and syscall specifications.

pub mod abi;
pub mod error;
pub mod syscall;
pub mod trace;

pub use abi::{
    descriptor, descriptor_from_raw, AbiFeatureSet, AbiHeader, AbiVersion, AlaniStatus, AuditEvent,
    AuditHandle, CapabilityHandle, CapabilityRights, DeviceHandle, ExecutionContext, Handle,
    InferenceBudget, IntentHandle, MemoryMapFlags, ModelHandle, ObjectHandle, ObjectKind,
    SharedMemoryHandle, SysInfo, SyscallArgKind, SyscallDescriptor, SyscallFrame, SyscallGroup,
    SyscallNumber, SyscallReturn, TaskHandle, TaskSpawnOptions, TaskState, TraceContext,
    UserBuffer, ABI_FEATURE_AUDIT_METADATA, ABI_FEATURE_CAPABILITY_HANDLES,
    ABI_FEATURE_INFERENCE_BUDGETS, ABI_FEATURE_SYSCALL_TABLE, ABI_FEATURE_TRACE_CONTEXT,
    ABI_FEATURE_USER_BUFFERS, ABI_KNOWN_FEATURES, ALANI_ABI_FEATURES, ALANI_ABI_MAJOR,
    ALANI_ABI_MINOR, ALANI_ABI_PATCH, ALANI_ABI_VERSION, CAP_ATTEST, CAP_AUDIT_APPEND,
    CAP_AUDIT_QUERY, CAP_AUDIT_VERIFY, CAP_CAPABILITY_ADMIN, CAP_COGNITION_INFER,
    CAP_COGNITION_MEMORY_WRITE, CAP_DEVICE_CALL, CAP_DEVICE_LIST, CAP_DEVICE_OPEN, CAP_MEMORY_MAP,
    CAP_MEMORY_SHARE, CAP_RANDOM, CAP_TASK_MANAGE, CAP_TASK_SPAWN, CAP_TRACE_CONTEXT,
    DEFAULT_MAX_USER_BUFFER_LEN, INFERENCE_FLAG_CACHE_ALLOWED, INFERENCE_FLAG_DETERMINISTIC,
    INFERENCE_KNOWN_FLAGS, KNOWN_CAPABILITY_RIGHTS, SYSCALL_CONTEXT_EARLY_BOOT,
    SYSCALL_CONTEXT_INTERRUPT, SYSCALL_CONTEXT_KNOWN_FLAGS, SYSCALL_CONTEXT_TASK, SYSCALL_TABLE,
    SYSCALL_TABLE_LEN, SYSCALL_TABLE_VERSION, TRACE_FLAG_DEBUG, TRACE_FLAG_SAMPLED,
    TRACE_KNOWN_FLAGS, USER_BUFFER_KNOWN_FLAGS, USER_BUFFER_PINNABLE, USER_BUFFER_READ,
    USER_BUFFER_WRITE,
};
pub use error::{status_to_result, AlaniError, AlaniResult};
pub use syscall::{AlaniClient, SyscallTransport, UnsupportedTransport};
pub use trace::{
    Component, DataClass, EventEnvelope, LogLevel, MetricSample, MetricUnit, RedactionPolicy,
    Severity, TraceIdGenerator, REDACTED, REDACTION_REASON_SENSITIVE,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-lib";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this crate.
pub const MODULES: &[&str] = &["abi", "error", "syscall", "trace"];

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}
