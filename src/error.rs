//! Shared error vocabulary and result helpers.
//!
//! `AlaniError` is richer than the ABI status enum, but every kernel-facing
//! variant maps back to a stable status code.

use crate::abi::AlaniStatus;

/// Shared library error taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlaniError {
    /// The kernel returned `InvalidArgument`.
    InvalidArgument,
    /// ABI version fields or compatibility checks failed.
    InvalidVersion,
    /// The kernel returned `PermissionDenied`.
    PermissionDenied,
    /// A capability handle did not include required rights.
    MissingCapability,
    /// The kernel returned `NotFound`.
    NotFound,
    /// The kernel returned `Busy`.
    Busy,
    /// A fixed-capacity table or subsystem cannot currently make progress.
    CapacityExceeded,
    /// The kernel returned `DeadlineExceeded`.
    DeadlineExceeded,
    /// The kernel returned `Internal`.
    Internal,
    /// The syscall transport is not available on this target.
    Unsupported,
    /// A user buffer descriptor is invalid.
    InvalidBuffer,
    /// A user buffer exceeds the compatibility ceiling.
    BufferTooLarge,
    /// Reserved bits or fields were set.
    ReservedBits,
    /// A returned integer was outside the known enum range.
    InvalidValue,
    /// A handle was zero or otherwise invalid for this helper.
    InvalidHandle,
    /// A trace context failed validation.
    InvalidTrace,
    /// A syscall number is not present in the public table.
    UnknownSyscall,
    /// A syscall was invoked from a forbidden execution context.
    InvalidContext,
    /// A budget descriptor failed validation.
    InvalidBudget,
    /// A wrapper was called with an invalid option combination.
    InvalidOptions,
}

impl AlaniError {
    /// Converts a kernel status to a shared error.
    pub const fn from_status(status: AlaniStatus) -> Self {
        match status {
            AlaniStatus::Ok => Self::InvalidValue,
            AlaniStatus::InvalidArgument => Self::InvalidArgument,
            AlaniStatus::PermissionDenied => Self::PermissionDenied,
            AlaniStatus::NotFound => Self::NotFound,
            AlaniStatus::Busy => Self::Busy,
            AlaniStatus::DeadlineExceeded => Self::DeadlineExceeded,
            AlaniStatus::Internal => Self::Internal,
        }
    }

    /// Maps this error to the closest stable ABI status.
    pub const fn status(self) -> AlaniStatus {
        match self {
            Self::InvalidArgument
            | Self::InvalidVersion
            | Self::InvalidBuffer
            | Self::BufferTooLarge
            | Self::ReservedBits
            | Self::InvalidValue
            | Self::InvalidHandle
            | Self::InvalidTrace
            | Self::UnknownSyscall
            | Self::InvalidContext
            | Self::InvalidBudget
            | Self::InvalidOptions => AlaniStatus::InvalidArgument,
            Self::PermissionDenied | Self::MissingCapability => AlaniStatus::PermissionDenied,
            Self::NotFound => AlaniStatus::NotFound,
            Self::Busy | Self::CapacityExceeded => AlaniStatus::Busy,
            Self::DeadlineExceeded => AlaniStatus::DeadlineExceeded,
            Self::Internal | Self::Unsupported => AlaniStatus::Internal,
        }
    }

    /// Stable reason label for logs, tests, and future audit records.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidVersion => "invalid_version",
            Self::PermissionDenied => "permission_denied",
            Self::MissingCapability => "missing_capability",
            Self::NotFound => "not_found",
            Self::Busy => "busy",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Internal => "internal",
            Self::Unsupported => "unsupported",
            Self::InvalidBuffer => "invalid_buffer",
            Self::BufferTooLarge => "buffer_too_large",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidValue => "invalid_value",
            Self::InvalidHandle => "invalid_handle",
            Self::InvalidTrace => "invalid_trace",
            Self::UnknownSyscall => "unknown_syscall",
            Self::InvalidContext => "invalid_context",
            Self::InvalidBudget => "invalid_budget",
            Self::InvalidOptions => "invalid_options",
        }
    }
}

impl From<AlaniStatus> for AlaniError {
    fn from(status: AlaniStatus) -> Self {
        Self::from_status(status)
    }
}

impl From<AlaniError> for AlaniStatus {
    fn from(error: AlaniError) -> Self {
        error.status()
    }
}

impl core::fmt::Display for AlaniError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AlaniError {}

/// Result alias used by shared wrappers.
pub type AlaniResult<T> = Result<T, AlaniError>;

/// Converts a kernel status into an empty result.
pub const fn status_to_result(status: AlaniStatus) -> AlaniResult<()> {
    if status.is_ok() {
        Ok(())
    } else {
        Err(AlaniError::from_status(status))
    }
}
