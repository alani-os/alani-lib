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
    /// The kernel returned `PermissionDenied`.
    PermissionDenied,
    /// The kernel returned `NotFound`.
    NotFound,
    /// The kernel returned `Busy`.
    Busy,
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
            | Self::InvalidBuffer
            | Self::BufferTooLarge
            | Self::ReservedBits
            | Self::InvalidValue
            | Self::InvalidHandle
            | Self::InvalidTrace
            | Self::InvalidOptions => AlaniStatus::InvalidArgument,
            Self::PermissionDenied => AlaniStatus::PermissionDenied,
            Self::NotFound => AlaniStatus::NotFound,
            Self::Busy => AlaniStatus::Busy,
            Self::DeadlineExceeded => AlaniStatus::DeadlineExceeded,
            Self::Internal | Self::Unsupported => AlaniStatus::Internal,
        }
    }

    /// Stable reason label for logs, tests, and future audit records.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::Busy => "busy",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Internal => "internal",
            Self::Unsupported => "unsupported",
            Self::InvalidBuffer => "invalid_buffer",
            Self::BufferTooLarge => "buffer_too_large",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidValue => "invalid_value",
            Self::InvalidHandle => "invalid_handle",
            Self::InvalidTrace => "invalid_trace",
            Self::InvalidOptions => "invalid_options",
        }
    }
}

impl From<AlaniStatus> for AlaniError {
    fn from(status: AlaniStatus) -> Self {
        Self::from_status(status)
    }
}

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
