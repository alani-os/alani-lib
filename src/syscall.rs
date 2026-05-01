//! Safe syscall wrapper surface.
//!
//! Real architecture-specific syscall instructions are intentionally outside
//! this dependency-free skeleton. Wrappers call a [`SyscallTransport`] so host
//! tests, simulators, and future platform shims can share the same safe API.

use crate::abi::{
    CapabilityHandle, DeviceHandle, Handle, InferenceBudget, MemoryMapFlags, ModelHandle,
    SharedMemoryHandle, SysInfo, SyscallFrame, SyscallNumber, SyscallReturn, TaskHandle, TaskState,
    TraceContext, UserBuffer, USER_BUFFER_READ, USER_BUFFER_WRITE,
};
use crate::error::{AlaniError, AlaniResult};

/// Transport boundary between safe wrappers and the target syscall mechanism.
pub trait SyscallTransport {
    /// Invokes one syscall frame and returns raw ABI result registers.
    fn invoke(&mut self, frame: SyscallFrame) -> SyscallReturn;
}

/// Transport implementation used when no syscall mechanism is available.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnsupportedTransport;

impl SyscallTransport for UnsupportedTransport {
    fn invoke(&mut self, _frame: SyscallFrame) -> SyscallReturn {
        SyscallReturn::error(crate::abi::AlaniStatus::Internal)
    }
}

/// Safe syscall client over an injectable transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlaniClient<T> {
    transport: T,
    trace: TraceContext,
}

impl<T: SyscallTransport> AlaniClient<T> {
    /// Creates a client with an empty trace context.
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            trace: TraceContext::EMPTY,
        }
    }

    /// Creates a client with a trace context.
    pub const fn with_trace(transport: T, trace: TraceContext) -> Self {
        Self { transport, trace }
    }

    /// Returns the current trace context.
    pub const fn trace(&self) -> TraceContext {
        self.trace
    }

    /// Replaces the current trace context after validation.
    pub fn set_trace(&mut self, trace: TraceContext) -> AlaniResult<()> {
        if trace.reserved != 0 {
            return Err(AlaniError::InvalidTrace);
        }
        self.trace = trace;
        Ok(())
    }

    /// Mutable access to the underlying transport for host tests.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consumes the client and returns the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Calls `sys_info`.
    pub fn sys_info(&mut self, out: &mut [u8]) -> AlaniResult<SysInfo> {
        let out = UserBuffer::write_only(out)?;
        let ret = self.invoke(
            SyscallNumber::SysInfo,
            [out.ptr, out.len, out.flags as u64, 0, 0, 0],
        )?;
        Ok(SysInfo::from_return(ret))
    }

    /// Calls `sys_yield`.
    pub fn sys_yield(&mut self) -> AlaniResult<()> {
        self.invoke(SyscallNumber::SysYield, [0; 6])?;
        Ok(())
    }

    /// Calls `sys_exit`.
    pub fn sys_exit(&mut self, code: u64) -> AlaniResult<()> {
        self.invoke(SyscallNumber::SysExit, [code, 0, 0, 0, 0, 0])?;
        Ok(())
    }

    /// Calls `sys_time` and returns monotonic time from the kernel.
    pub fn sys_time(&mut self) -> AlaniResult<u64> {
        Ok(self.invoke(SyscallNumber::SysTime, [0; 6])?.value)
    }

    /// Calls `sys_trace_context` and installs `trace` locally after validation.
    pub fn sys_trace_context(&mut self, trace: TraceContext) -> AlaniResult<TraceContext> {
        trace.validate()?;
        let ret = self.invoke_with_trace(SyscallNumber::SysTraceContext, [0; 6], trace)?;
        self.trace = trace;
        Ok(TraceContext::root(ret.value, ret.detail))
    }

    /// Calls `sys_task_spawn` with a manifest buffer and priority.
    pub fn sys_task_spawn(&mut self, manifest: &[u8], priority: u8) -> AlaniResult<TaskHandle> {
        let manifest = UserBuffer::read_only(manifest)?;
        let ret = self.invoke(
            SyscallNumber::SysTaskSpawn,
            [manifest.ptr, manifest.len, 0, u64::from(priority), 0, 0],
        )?;
        Ok(Handle(ret.value))
    }

    /// Calls `sys_task_join`.
    pub fn sys_task_join(&mut self, task: TaskHandle) -> AlaniResult<()> {
        validate_handle(task)?;
        self.invoke(SyscallNumber::SysTaskJoin, [task.0, 0, 0, 0, 0, 0])?;
        Ok(())
    }

    /// Calls `sys_task_cancel`.
    pub fn sys_task_cancel(&mut self, task: TaskHandle) -> AlaniResult<()> {
        validate_handle(task)?;
        self.invoke(SyscallNumber::SysTaskCancel, [task.0, 0, 0, 0, 0, 0])?;
        Ok(())
    }

    /// Calls `sys_task_status`.
    pub fn sys_task_status(&mut self, task: TaskHandle) -> AlaniResult<TaskState> {
        validate_handle(task)?;
        let ret = self.invoke(SyscallNumber::SysTaskStatus, [task.0, 0, 0, 0, 0, 0])?;
        TaskState::from_raw(ret.value)
    }

    /// Calls `sys_mem_map`.
    pub fn sys_mem_map(&mut self, addr: u64, len: u64, flags: MemoryMapFlags) -> AlaniResult<u64> {
        flags.validate()?;
        validate_range(addr, len)?;
        Ok(self
            .invoke(SyscallNumber::SysMemMap, [addr, len, flags.bits(), 0, 0, 0])?
            .value)
    }

    /// Calls `sys_mem_unmap`.
    pub fn sys_mem_unmap(&mut self, addr: u64, len: u64) -> AlaniResult<()> {
        validate_range(addr, len)?;
        self.invoke(SyscallNumber::SysMemUnmap, [addr, len, 0, 0, 0, 0])?;
        Ok(())
    }

    /// Calls `sys_mem_query`.
    pub fn sys_mem_query(&mut self) -> AlaniResult<(u64, u64)> {
        let ret = self.invoke(SyscallNumber::SysMemQuery, [0; 6])?;
        Ok((ret.value, ret.detail))
    }

    /// Calls `sys_mem_share`.
    pub fn sys_mem_share(
        &mut self,
        addr: u64,
        len: u64,
        flags: MemoryMapFlags,
    ) -> AlaniResult<SharedMemoryHandle> {
        flags.validate()?;
        validate_range(addr, len)?;
        let ret = self.invoke(
            SyscallNumber::SysMemShare,
            [addr, len, flags.bits(), 0, 0, 0],
        )?;
        Ok(Handle(ret.value))
    }

    /// Calls `sys_mem_seal`.
    pub fn sys_mem_seal(&mut self, handle: SharedMemoryHandle) -> AlaniResult<()> {
        validate_handle(handle)?;
        self.invoke(SyscallNumber::SysMemSeal, [handle.0, 0, 0, 0, 0, 0])?;
        Ok(())
    }

    /// Calls `sys_device_list`.
    pub fn sys_device_list(&mut self, out: &mut [u8]) -> AlaniResult<usize> {
        let out = UserBuffer::write_only(out)?;
        let ret = self.invoke(
            SyscallNumber::SysDeviceList,
            [out.ptr, out.len, out.flags as u64, 0, 0, 0],
        )?;
        usize::try_from(ret.value).map_err(|_| AlaniError::InvalidValue)
    }

    /// Calls `sys_device_open`.
    pub fn sys_device_open(&mut self, device_id: u64) -> AlaniResult<DeviceHandle> {
        if device_id == 0 {
            return Err(AlaniError::InvalidHandle);
        }
        let ret = self.invoke(SyscallNumber::SysDeviceOpen, [device_id, 0, 0, 0, 0, 0])?;
        Ok(Handle(ret.value))
    }

    /// Calls `sys_device_call`.
    pub fn sys_device_call(
        &mut self,
        device: DeviceHandle,
        opcode: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> AlaniResult<usize> {
        validate_handle(device)?;
        let input = UserBuffer::read_only(input)?;
        let output = UserBuffer::write_only(output)?;
        let ret = self.invoke(
            SyscallNumber::SysDeviceCall,
            [
                device.0, opcode, input.ptr, input.len, output.ptr, output.len,
            ],
        )?;
        usize::try_from(ret.detail).map_err(|_| AlaniError::InvalidValue)
    }

    /// Calls `sys_device_close`.
    pub fn sys_device_close(&mut self, device: DeviceHandle) -> AlaniResult<()> {
        validate_handle(device)?;
        self.invoke(SyscallNumber::SysDeviceClose, [device.0, 0, 0, 0, 0, 0])?;
        Ok(())
    }

    /// Calls `sys_model_list`.
    pub fn sys_model_list(&mut self, out: &mut [u8]) -> AlaniResult<usize> {
        let out = UserBuffer::write_only(out)?;
        let ret = self.invoke(
            SyscallNumber::SysModelList,
            [out.ptr, out.len, out.flags as u64, 0, 0, 0],
        )?;
        usize::try_from(ret.value).map_err(|_| AlaniError::InvalidValue)
    }

    /// Calls `sys_model_open`.
    pub fn sys_model_open(&mut self, model_id: u64) -> AlaniResult<ModelHandle> {
        if model_id == 0 {
            return Err(AlaniError::InvalidHandle);
        }
        let ret = self.invoke(SyscallNumber::SysModelOpen, [model_id, 0, 0, 0, 0, 0])?;
        Ok(Handle(ret.value))
    }

    /// Calls `sys_infer`.
    pub fn sys_infer(
        &mut self,
        model: ModelHandle,
        request: &[u8],
        output: &mut [u8],
        budget: InferenceBudget,
    ) -> AlaniResult<usize> {
        validate_handle(model)?;
        budget.validate()?;
        let request = UserBuffer::read_only(request)?;
        let output = UserBuffer::write_only(output)?;
        let packed_budget =
            (u64::from(budget.max_tokens) << 32) | u64::from(budget.max_compute_units);
        let deadline_or_budget = if budget.deadline_ns != 0 {
            budget.deadline_ns
        } else {
            packed_budget
        };
        let ret = self.invoke(
            SyscallNumber::SysInfer,
            [
                model.0,
                request.ptr,
                request.len,
                deadline_or_budget,
                output.ptr,
                output.len,
            ],
        )?;
        usize::try_from(ret.detail.max(ret.value)).map_err(|_| AlaniError::InvalidValue)
    }

    /// Calls `sys_memory_query`.
    pub fn sys_memory_query(&mut self, query: &[u8], output: &mut [u8]) -> AlaniResult<usize> {
        let query = UserBuffer::read_only(query)?;
        let output = UserBuffer::write_only(output)?;
        let ret = self.invoke(
            SyscallNumber::SysMemoryQuery,
            [query.ptr, query.len, output.ptr, output.len, 0, 0],
        )?;
        usize::try_from(ret.detail.max(ret.value)).map_err(|_| AlaniError::InvalidValue)
    }

    /// Calls `sys_memory_put`.
    pub fn sys_memory_put(&mut self, record: &[u8]) -> AlaniResult<Handle> {
        let record = UserBuffer::read_only(record)?;
        let ret = self.invoke(
            SyscallNumber::SysMemoryPut,
            [record.ptr, record.len, 0, 0, 0, 0],
        )?;
        Ok(Handle(ret.value))
    }

    /// Calls `sys_cap_derive`.
    pub fn sys_cap_derive(
        &mut self,
        parent: CapabilityHandle,
        requested_rights: u64,
    ) -> AlaniResult<CapabilityHandle> {
        if !parent.is_valid() || requested_rights == 0 {
            return Err(AlaniError::InvalidHandle);
        }
        let ret = self.invoke(
            SyscallNumber::SysCapDerive,
            [
                parent.id,
                parent.generation as u64,
                requested_rights,
                0,
                0,
                0,
            ],
        )?;
        Ok(CapabilityHandle {
            id: ret.value,
            rights: requested_rights,
            owner_task: 0,
            generation: ret.detail as u32,
        })
    }

    /// Calls `sys_cap_revoke`.
    pub fn sys_cap_revoke(&mut self, handle: CapabilityHandle) -> AlaniResult<()> {
        if !handle.is_valid() {
            return Err(AlaniError::InvalidHandle);
        }
        self.invoke(
            SyscallNumber::SysCapRevoke,
            [handle.id, handle.generation as u64, 0, 0, 0, 0],
        )?;
        Ok(())
    }

    /// Calls `sys_attest`.
    pub fn sys_attest(&mut self, output: &mut [u8]) -> AlaniResult<usize> {
        let output = UserBuffer::write_only(output)?;
        let ret = self.invoke(
            SyscallNumber::SysAttest,
            [output.ptr, output.len, output.flags as u64, 0, 0, 0],
        )?;
        usize::try_from(ret.detail.max(ret.value)).map_err(|_| AlaniError::InvalidValue)
    }

    /// Calls `sys_random`.
    pub fn sys_random(&mut self, output: &mut [u8]) -> AlaniResult<usize> {
        let output = UserBuffer::write_only(output)?;
        let ret = self.invoke(
            SyscallNumber::SysRandom,
            [output.ptr, output.len, output.flags as u64, 0, 0, 0],
        )?;
        usize::try_from(ret.detail.max(ret.value)).map_err(|_| AlaniError::InvalidValue)
    }

    /// Calls `sys_audit_append`.
    pub fn sys_audit_append(&mut self, record: &[u8]) -> AlaniResult<u64> {
        let record = UserBuffer::read_only(record)?;
        Ok(self
            .invoke(
                SyscallNumber::SysAuditAppend,
                [record.ptr, record.len, USER_BUFFER_READ as u64, 0, 0, 0],
            )?
            .value)
    }

    /// Calls `sys_audit_query`.
    pub fn sys_audit_query(
        &mut self,
        start: u64,
        end: u64,
        output: &mut [u8],
    ) -> AlaniResult<usize> {
        validate_ordered_range(start, end)?;
        let output = UserBuffer::write_only(output)?;
        let ret = self.invoke(
            SyscallNumber::SysAuditQuery,
            [
                start,
                end,
                output.ptr,
                output.len,
                USER_BUFFER_WRITE as u64,
                0,
            ],
        )?;
        usize::try_from(ret.detail.max(ret.value)).map_err(|_| AlaniError::InvalidValue)
    }

    /// Calls `sys_audit_verify`.
    pub fn sys_audit_verify(
        &mut self,
        start: u64,
        end: u64,
        output: &mut [u8],
    ) -> AlaniResult<usize> {
        validate_ordered_range(start, end)?;
        let output = UserBuffer::write_only(output)?;
        let ret = self.invoke(
            SyscallNumber::SysAuditVerify,
            [
                start,
                end,
                output.ptr,
                output.len,
                USER_BUFFER_WRITE as u64,
                0,
            ],
        )?;
        usize::try_from(ret.detail.max(ret.value)).map_err(|_| AlaniError::InvalidValue)
    }

    fn invoke(&mut self, number: SyscallNumber, args: [u64; 6]) -> AlaniResult<SyscallReturn> {
        self.invoke_with_trace(number, args, self.trace)
    }

    fn invoke_with_trace(
        &mut self,
        number: SyscallNumber,
        args: [u64; 6],
        trace: TraceContext,
    ) -> AlaniResult<SyscallReturn> {
        trace.validate()?;
        let frame = SyscallFrame::new(number, args, trace);
        self.transport.invoke(frame).into_result()
    }
}

fn validate_handle(handle: Handle) -> AlaniResult<()> {
    if handle.is_valid() {
        Ok(())
    } else {
        Err(AlaniError::InvalidHandle)
    }
}

fn validate_range(start: u64, len: u64) -> AlaniResult<()> {
    if start == 0 || len == 0 || start.checked_add(len).is_none() {
        Err(AlaniError::InvalidArgument)
    } else {
        Ok(())
    }
}

fn validate_ordered_range(start: u64, end: u64) -> AlaniResult<()> {
    if end < start {
        Err(AlaniError::InvalidArgument)
    } else {
        Ok(())
    }
}
