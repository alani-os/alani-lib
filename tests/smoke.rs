use core::mem::{align_of, size_of};

use alani_lib::abi::{
    descriptor, AbiFeatureSet, AbiHeader, AbiVersion, AlaniStatus, CapabilityHandle,
    CapabilityRights, ExecutionContext, InferenceBudget, MemoryMapFlags, ObjectHandle, ObjectKind,
    SysInfo, SyscallFrame, SyscallNumber, SyscallReturn, TraceContext, UserBuffer,
    ABI_FEATURE_USER_BUFFERS, ABI_KNOWN_FEATURES, CAP_COGNITION_INFER, CAP_DEVICE_CALL,
    CAP_TASK_SPAWN, DEFAULT_MAX_USER_BUFFER_LEN, INFERENCE_FLAG_DETERMINISTIC, SYSCALL_TABLE,
    SYSCALL_TABLE_LEN, TRACE_FLAG_SAMPLED, USER_BUFFER_READ, USER_BUFFER_WRITE,
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
    assert!(alani_lib::ALANI_ABI_VERSION.is_compatible_with(AbiVersion::new(0, 1, 0)));
    assert_eq!(
        AbiVersion {
            flags: 1,
            ..alani_lib::ALANI_ABI_VERSION
        }
        .validate(),
        Err(AlaniError::ReservedBits)
    );

    let header = AbiHeader::new(
        size_of::<AbiHeader>() as u32,
        0,
        alani_lib::ALANI_ABI_VERSION,
    );
    assert_eq!(header.validate(size_of::<AbiHeader>() as u32, 0), Ok(()));

    let features = AbiFeatureSet::from_bits(alani_lib::ALANI_ABI_FEATURES).unwrap();
    assert!(features.contains(AbiFeatureSet(ABI_FEATURE_USER_BUFFERS)));
    assert_eq!(
        AbiFeatureSet::from_bits(ABI_KNOWN_FEATURES << 1),
        Err(AlaniError::ReservedBits)
    );
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
    assert_eq!(write.checked_end(), Ok(write.ptr + write.len));
    assert_eq!(write.validate_alignment(1), Ok(()));

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
    assert_eq!(
        UserBuffer::new(0x1000, 16, 0).validate(),
        Err(AlaniError::InvalidBuffer)
    );
    assert_eq!(
        UserBuffer::new(0x1000, DEFAULT_MAX_USER_BUFFER_LEN + 1, USER_BUFFER_READ).validate(),
        Err(AlaniError::BufferTooLarge)
    );
    assert_eq!(
        UserBuffer::new(u64::MAX, 16, USER_BUFFER_READ).validate(),
        Err(AlaniError::InvalidBuffer)
    );
    assert_eq!(
        UserBuffer::new(0x1003, 16, USER_BUFFER_READ).validate_alignment(4),
        Err(AlaniError::InvalidBuffer)
    );
}

#[test]
fn syscall_number_group_and_names_match_spec() {
    assert_eq!(
        SyscallNumber::from_raw(0x0400),
        Some(SyscallNumber::SysInfer)
    );
    assert_eq!(
        SyscallNumber::from_raw(0x0401),
        Some(SyscallNumber::SysModelList)
    );
    assert_eq!(
        SyscallNumber::from_raw(0x0402),
        Some(SyscallNumber::SysModelOpen)
    );
    assert_eq!(SyscallNumber::SysAuditVerify.name(), "sys_audit_verify");
    assert_eq!(
        SyscallNumber::SysDeviceCall.group(),
        alani_lib::abi::SyscallGroup::Device
    );
    assert_eq!(SYSCALL_TABLE.len(), SYSCALL_TABLE_LEN);
    for entry in SYSCALL_TABLE {
        assert_eq!(entry.validate(), Ok(()));
        assert_eq!(entry.name, entry.number.name());
        assert_eq!(descriptor(entry.number), Some(&entry));
    }

    let infer = descriptor(SyscallNumber::SysInfer).unwrap();
    assert!(infer
        .required_rights
        .contains(CapabilityRights(CAP_COGNITION_INFER)));
    assert!(infer.requires_capability());
    assert!(infer.requires_audit());
    assert!(infer.allows_context(ExecutionContext::Task));
    assert!(!infer.allows_context(ExecutionContext::EarlyBoot));
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
    assert_eq!(frame.args[2], 0);
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
fn task_spawn_wrapper_uses_manifest_pointer_length_and_options_pointer() {
    let mut client = AlaniClient::new(RecordingTransport::new(SyscallReturn::ok(42, 0)));
    let manifest = b"init=/bin/alani-init";
    let handle = client.sys_task_spawn(manifest, 7).unwrap();
    assert_eq!(handle.0, 42);

    let frame = client.into_transport().last_frame.unwrap();
    assert_eq!(frame.number, SyscallNumber::SysTaskSpawn as u64);
    assert_eq!(frame.args[1], manifest.len() as u64);
    assert_ne!(frame.args[2], 0);
    assert_eq!(frame.args[3], 0);
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
    let parent = CapabilityHandle::new(
        10,
        CapabilityRights(CAP_TASK_SPAWN | CAP_DEVICE_CALL | CAP_COGNITION_INFER),
        1,
        2,
    );
    let child = client.sys_cap_derive(parent, CAP_COGNITION_INFER).unwrap();
    assert_eq!(child.id, 55);
    assert_eq!(child.rights, CAP_COGNITION_INFER);
    assert_eq!(child.owner_task, 1);
    assert_eq!(child.generation, 3);
}

#[test]
fn trace_context_generator_and_redaction_work() {
    let mut ids = TraceIdGenerator::new();
    let root = ids.next_root();
    let child = ids.next_child(root);
    assert_eq!(child.trace_id, root.trace_id);
    assert_eq!(child.parent_span_id, root.span_id);
    assert_eq!(root.flags, TRACE_FLAG_SAMPLED);

    let event = EventEnvelope::new(1, child, Component::new("runtime.syscall"), "sys_infer")
        .timestamp_ns(100)
        .monotonic_counter(2)
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
    assert_eq!(
        event.redaction_reason,
        alani_lib::REDACTION_REASON_SENSITIVE
    );
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

#[test]
fn capability_and_dispatch_validation_fail_closed() {
    assert_eq!(
        alani_lib::Handle::INVALID.validate(),
        Err(AlaniError::InvalidHandle)
    );
    assert_eq!(
        CapabilityRights::from_bits(1 << 63),
        Err(AlaniError::ReservedBits)
    );

    let cap = CapabilityHandle::new(9, CapabilityRights(CAP_COGNITION_INFER), 42, 1);
    let frame = SyscallFrame::untraced(SyscallNumber::SysInfer, [0; 6]);
    assert_eq!(
        frame.validate_for_context(ExecutionContext::EarlyBoot),
        Err(AlaniError::InvalidContext)
    );
    assert_eq!(
        frame.validate_dispatch(ExecutionContext::Task, None),
        Err(AlaniError::MissingCapability)
    );
    assert_eq!(
        frame
            .validate_dispatch(ExecutionContext::Task, Some(cap))
            .unwrap()
            .number,
        SyscallNumber::SysInfer
    );

    let object = ObjectHandle::new(alani_lib::Handle::new(11), ObjectKind::Device);
    assert_eq!(object.validate(), Ok(()));
    assert_eq!(ObjectKind::from_raw(4), Some(ObjectKind::Model));
    assert_eq!(ObjectKind::from_raw(99), None);
}

#[test]
fn trace_budget_sys_info_and_layouts_validate() {
    assert_eq!(
        TraceContext {
            trace_id: 1,
            span_id: 0,
            parent_span_id: 0,
            flags: 0,
            reserved: 0,
        }
        .validate(),
        Err(AlaniError::InvalidTrace)
    );

    let budget = InferenceBudget::bounded(256, 1_000, 99).deterministic();
    assert_eq!(budget.flags, INFERENCE_FLAG_DETERMINISTIC);
    assert_eq!(budget.validate(), Ok(()));

    let info = SysInfo::CURRENT;
    assert_eq!(info.validate(), Ok(()));
    assert_eq!(info.syscall_count, SYSCALL_TABLE_LEN as u32);
    assert_eq!(info.max_user_buffer_len, DEFAULT_MAX_USER_BUFFER_LEN);

    assert_eq!(SyscallReturn::ok(7, 8).validate(), Ok(()));
    assert_eq!(
        SyscallReturn {
            reserved: 1,
            ..SyscallReturn::ok(0, 0)
        }
        .validate(),
        Err(AlaniError::ReservedBits)
    );

    assert_eq!(size_of::<AbiVersion>(), 8);
    assert_eq!(size_of::<AbiHeader>(), 24);
    assert_eq!(size_of::<CapabilityHandle>(), 32);
    assert_eq!(size_of::<ObjectHandle>(), 16);
    assert_eq!(size_of::<UserBuffer>(), 24);
    assert_eq!(size_of::<TraceContext>(), 32);
    assert_eq!(size_of::<InferenceBudget>(), 24);
    assert_eq!(size_of::<SyscallFrame>(), 88);
    assert_eq!(size_of::<SyscallReturn>(), 24);
    assert_eq!(size_of::<SysInfo>(), 48);
    assert_eq!(align_of::<SyscallFrame>(), 8);
}
