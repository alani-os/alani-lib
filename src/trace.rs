//! Trace context and structured event helpers.
//!
//! This module keeps observability payloads small and explicit. Sensitive and
//! secret data are redacted by default before an event leaves a trust boundary.

pub use crate::abi::TraceContext;

use crate::error::{AlaniError, AlaniResult};

/// Event severity.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    /// Verbose debug event.
    Debug,
    /// Informational event.
    Info,
    /// Operational notice.
    Notice,
    /// Recoverable warning.
    Warning,
    /// Error.
    Error,
    /// Security or integrity critical event.
    Critical,
}

/// Data classification for event fields.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataClass {
    /// Safe for public release.
    Public,
    /// Operational metadata.
    Operational,
    /// Sensitive data that requires policy-controlled export.
    Sensitive,
    /// Secret data that must not be exported.
    Secret,
}

/// Redaction policy applied to structured events.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionPolicy {
    /// Redact sensitive and secret fields.
    DefaultDeny,
    /// Redact only secret fields.
    OperationalExport,
    /// Export everything. Use only for controlled test fixtures.
    UnredactedTestOnly,
}

impl RedactionPolicy {
    /// Returns `true` when data with `class` must be redacted.
    pub const fn redacts(self, class: DataClass) -> bool {
        match self {
            Self::DefaultDeny => matches!(class, DataClass::Sensitive | DataClass::Secret),
            Self::OperationalExport => matches!(class, DataClass::Secret),
            Self::UnredactedTestOnly => false,
        }
    }
}

/// Stable redacted value used by event helpers.
pub const REDACTED: &str = "[redacted]";

/// Component label for structured events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Component<'a> {
    /// Component name, for example `runtime.syscall`.
    pub name: &'a str,
}

impl<'a> Component<'a> {
    /// Creates a component label.
    pub const fn new(name: &'a str) -> Self {
        Self { name }
    }
}

/// Structured event envelope for host tests and future telemetry adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventEnvelope<'a> {
    /// Schema version label.
    pub schema_version: &'static str,
    /// Event identifier.
    pub event_id: u64,
    /// Trace context.
    pub trace: TraceContext,
    /// Component name.
    pub component: Component<'a>,
    /// Operation name.
    pub operation: &'a str,
    /// Principal label.
    pub principal: &'a str,
    /// Resource label.
    pub resource: &'a str,
    /// Decision label such as `allow` or `deny`.
    pub decision: &'a str,
    /// Status label.
    pub status: &'a str,
    /// Event severity.
    pub severity: Severity,
    /// Data classification.
    pub data_class: DataClass,
    /// Human-readable payload after redaction.
    pub payload: &'a str,
}

impl<'a> EventEnvelope<'a> {
    /// Current schema version for event envelopes.
    pub const SCHEMA_VERSION: &'static str = "alani.event.v1";

    /// Creates a new structured event envelope.
    pub const fn new(
        event_id: u64,
        trace: TraceContext,
        component: Component<'a>,
        operation: &'a str,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            event_id,
            trace,
            component,
            operation,
            principal: "",
            resource: "",
            decision: "",
            status: "",
            severity: Severity::Info,
            data_class: DataClass::Operational,
            payload: "",
        }
    }

    /// Sets principal metadata.
    pub const fn principal(mut self, principal: &'a str) -> Self {
        self.principal = principal;
        self
    }

    /// Sets resource metadata.
    pub const fn resource(mut self, resource: &'a str) -> Self {
        self.resource = resource;
        self
    }

    /// Sets decision metadata.
    pub const fn decision(mut self, decision: &'a str) -> Self {
        self.decision = decision;
        self
    }

    /// Sets status metadata.
    pub const fn status(mut self, status: &'a str) -> Self {
        self.status = status;
        self
    }

    /// Sets severity.
    pub const fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets classified payload with a redaction policy.
    pub fn payload(
        mut self,
        data_class: DataClass,
        payload: &'a str,
        policy: RedactionPolicy,
    ) -> Self {
        self.data_class = data_class;
        self.payload = if policy.redacts(data_class) {
            REDACTED
        } else {
            payload
        };
        self
    }

    /// Validates event fields that cross repository boundaries.
    pub const fn validate(self) -> AlaniResult<()> {
        if self.schema_version.is_empty()
            || self.component.name.is_empty()
            || self.operation.is_empty()
        {
            return Err(AlaniError::InvalidValue);
        }
        self.trace.validate()
    }
}

/// Deterministic trace id generator for host tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceIdGenerator {
    next_trace_id: u64,
    next_span_id: u64,
}

impl TraceIdGenerator {
    /// Creates a generator starting at one.
    pub const fn new() -> Self {
        Self {
            next_trace_id: 1,
            next_span_id: 1,
        }
    }

    /// Creates the next root trace context.
    pub fn next_root(&mut self) -> TraceContext {
        let trace = TraceContext::root(self.next_trace_id, self.next_span_id);
        self.next_trace_id = self.next_trace_id.wrapping_add(1).max(1);
        self.next_span_id = self.next_span_id.wrapping_add(1).max(1);
        trace
    }

    /// Creates the next child context.
    pub fn next_child(&mut self, parent: TraceContext) -> TraceContext {
        let span_id = self.next_span_id;
        self.next_span_id = self.next_span_id.wrapping_add(1).max(1);
        parent.child(span_id)
    }
}

impl Default for TraceIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}
