use alani_lib::abi::{
    AbiVersion, AlaniStatus, CapabilityHandle, InferenceBudget, MemoryMapFlags, SyscallFrame,
    SyscallNumber, SyscallReturn, TraceContext, UserBuffer, USER_BUFFER_READ, USER_BUFFER_WRITE,
};
use alani_lib::error::{status_to_result, AlaniError};
use alani_lib::syscall::{AlaniClient, SyscallTransport};
use alani_lib::trace::{
    Component, DataClass, EventEnvelope, RedactionPolicy, Severity, TraceIdGenerator, REDACTED,
};

#[derive(Clone, Debug)]
struct RecordingTransport {
    last_frame: Option<SyscallFrame>,
    response: SyscallReturn,
}

impl RecordingTransport {
    fn new(response: SyscallReturn) -> Self {
        Self {
            last_frame: None,
            response,
        }
    }
}

impl SyscallTransport for RecordingTransport {
    fn invoke(&mut self, frame: SyscallFrame) -> SyscallReturn {
        self.last_frame = Some(frame);
        self.response
    }
}

#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_lib::repository_name(), "alani-lib");
    assert!(alani_lib::module_names().contains(&"abi"));
    assert!(alani_lib::module_names().contains(&"syscall"));
}

#[test]
fn abi_version_packs_and_unpacks() {
    let version = AbiVersion {
        major: 1,
        minor: 2,
        patch: 3,
        flags: 4,
    };
    assert_eq!(AbiVersion::from_packed(version.packed()), version);
}

#[test]
fn status_error_mapping_is_stable() {
    assert_eq!(
        status_to_result(AlaniStatus::PermissionDenied).unwrap_err(),
        AlaniError::PermissionDenied
    );
    assert_eq!(
        AlaniError::InvalidBuffer.status(),
        AlaniStatus::InvalidArgument
    );
}

#[test]
fn user_buffer_helpers_validate_direction_and_reserved_bits() {
    let bytes = [1_u8, 2, 3];
    let read = UserBuffer::read_only(&bytes).unwrap();
    assert!(read.is_readable());
    assert!(!read.is_writable());

    let mut out = [0_u8; 4];
    let write = UserBuffer::write_only(&mut out).unwrap();
    assert_eq!(write.flags, USER_BUFFER_WRITE);

    assert_eq!(
        UserBuffer {
            ptr: 1,
            len: 1,
            flags: USER_BUFFER_READ,
            reserved: 1,
        }
        .validate()
        .unwrap_err(),
        AlaniError::ReservedBits
    );
}

#[test]
fn syscall_number_group_and_names_match_spec() {
    assert_eq!(
        SyscallNumber::from_raw(0x0402),
        Some(SyscallNumber::SysInfer)
    );
    assert_eq!(SyscallNumber::SysAuditVerify.name(), "sys_audit_verify");
    assert_eq!(
        SyscallNumber::SysDeviceCall.group(),
        alani_lib::abi::SyscallGroup::Device
    );
}

#[test]
fn sys_info_wrapper_builds_output_buffer_frame() {
    let mut client = AlaniClient::new(RecordingTransport::new(SyscallReturn::ok(
        alani_lib::ALANI_ABI_VERSION.packed(),
        64,
    )));
    let mut out = [0_u8; 64];
    let info = client.sys_info(&mut out).unwrap();
    assert_eq!(info.abi_version, alani_lib::ALANI_ABI_VERSION);

    let transport = client.into_transport();
    let frame = transport.last_frame.unwrap();
    assert_eq!(frame.number, SyscallNumber::SysInfo as u64);
    assert_eq!(frame.args[1], 64);
    assert_eq!(frame.args[2], USER_BUFFER_WRITE as u64);
}

#[test]
fn wrapper_maps_kernel_error_status() {
    let mut client = AlaniClient::new(RecordingTransport::new(SyscallReturn::error(
        AlaniStatus::PermissionDenied,
    )));
    assert_eq!(
        client.sys_yield().unwrap_err(),
        AlaniError::PermissionDenied
    );
}

#[test]
fn task_spawn_wrapper_uses_manifest_pointer_length_and_priority() {
    let mut client = AlaniClient::new(RecordingTransport::new(SyscallReturn::ok(42, 0)));
    let manifest = b"init=/bin/alani-init";
    let handle = client.sys_task_spawn(manifest, 7).unwrap();
    assert_eq!(handle.0, 42);

    let frame = client.into_transport().last_frame.unwrap();
    assert_eq!(frame.number, SyscallNumber::SysTaskSpawn as u64);
    assert_eq!(frame.args[1], manifest.len() as u64);
    assert_eq!(frame.args[3], 7);
}

#[test]
fn invalid_handles_are_rejected_before_transport_call() {
    let mut client = AlaniClient::new(RecordingTransport::new(SyscallReturn::ok(0, 0)));
    assert_eq!(
        client
            .sys_task_cancel(alani_lib::TaskHandle::INVALID)
            .unwrap_err(),
        AlaniError::InvalidHandle
    );
    assert!(client.into_transport().last_frame.is_none());
}

#[test]
fn memory_flags_reject_unknown_bits() {
    assert_eq!(
        MemoryMapFlags::READ.union(MemoryMapFlags::WRITE).validate(),
        Ok(())
    );
    assert_eq!(
        MemoryMapFlags::from_bits(1 << 40).unwrap_err(),
        AlaniError::ReservedBits
    );
}

#[test]
fn infer_wrapper_validates_budget_and_packs_buffers() {
    let mut client = AlaniClient::new(RecordingTransport::new(SyscallReturn::ok(0, 12)));
    let request = b"hello";
    let mut output = [0_u8; 32];
    let written = client
        .sys_infer(
            alani_lib::Handle(9),
            request,
            &mut output,
            InferenceBudget::bounded(64, 100, 10_000),
        )
        .unwrap();
    assert_eq!(written, 12);

    let frame = client.into_transport().last_frame.unwrap();
    assert_eq!(frame.number, SyscallNumber::SysInfer as u64);
    assert_eq!(frame.args[0], 9);
    assert_eq!(frame.args[2], request.len() as u64);
    assert_eq!(frame.args[3], 10_000);
}

#[test]
fn capability_wrapper_returns_attenuated_handle_metadata() {
    let mut client = AlaniClient::new(RecordingTransport::new(SyscallReturn::ok(55, 3)));
    let child = client
        .sys_cap_derive(
            CapabilityHandle {
                id: 10,
                rights: 0b111,
                owner_task: 1,
                generation: 2,
            },
            0b001,
        )
        .unwrap();
    assert_eq!(child.id, 55);
    assert_eq!(child.rights, 0b001);
    assert_eq!(child.generation, 3);
}

#[test]
fn trace_context_generator_and_redaction_work() {
    let mut ids = TraceIdGenerator::new();
    let root = ids.next_root();
    let child = ids.next_child(root);
    assert_eq!(child.trace_id, root.trace_id);
    assert_eq!(child.parent_span_id, root.span_id);

    let event = EventEnvelope::new(1, child, Component::new("runtime.syscall"), "sys_infer")
        .principal("task:init")
        .resource("model:mock")
        .decision("allow")
        .status("ok")
        .severity(Severity::Notice)
        .payload(
            DataClass::Sensitive,
            "prompt text",
            RedactionPolicy::DefaultDeny,
        );
    assert_eq!(event.payload, REDACTED);
    event.validate().unwrap();
}

#[test]
fn trace_context_wrapper_propagates_trace() {
    let trace = TraceContext::root(100, 200);
    let mut client = AlaniClient::new(RecordingTransport::new(SyscallReturn::ok(100, 200)));
    let returned = client.sys_trace_context(trace).unwrap();
    assert_eq!(returned, trace);

    let frame = client.into_transport().last_frame.unwrap();
    assert_eq!(frame.trace, trace);
}
