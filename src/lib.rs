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
    AbiVersion, AlaniStatus, CapabilityHandle, DeviceHandle, Handle, InferenceBudget,
    MemoryMapFlags, ModelHandle, SharedMemoryHandle, SysInfo, SyscallFrame, SyscallGroup,
    SyscallNumber, SyscallReturn, TaskHandle, TaskState, TraceContext, UserBuffer,
    ALANI_ABI_VERSION,
};
pub use error::{status_to_result, AlaniError, AlaniResult};
pub use syscall::{AlaniClient, SyscallTransport, UnsupportedTransport};
pub use trace::{
    Component, DataClass, EventEnvelope, RedactionPolicy, Severity, TraceIdGenerator, REDACTED,
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
