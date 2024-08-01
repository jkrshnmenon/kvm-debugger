use memoffset::offset_of;
use kvm_bindings::kvm_regs;
use kvm_bindings::kvm_run;

pub const KVM_CREATE_VCPU: u64 = 0xAE41;
pub const KVM_GET_SREGS: u64 = 0x8138AE83;
pub const KVM_RUN: u64 = 0xAE80;
pub const KVM_GET_REGS: u64 = 0x8090AE81;
pub const KVM_SET_REGS: u64 = 0x4090AE82;
pub const KVM_SET_GUEST_DEBUG: u64 = 0x4048ae9b;


pub fn kvm_regs_size() -> usize {
    std::mem::size_of::<kvm_regs>()
}

pub fn kvm_regs_from_vec(vec: Vec<u8>) -> kvm_regs {
    unsafe { std::ptr::read(vec.as_ptr() as *const kvm_regs) }
}

pub fn kvm_regs_to_vec(regs: kvm_regs) -> Vec<u8> {
    let mut vec = Vec::with_capacity(kvm_regs_size());
    unsafe {
        vec.set_len(kvm_regs_size());
        std::ptr::write(vec.as_mut_ptr() as *mut kvm_regs, regs);
    }
    vec
}

pub fn kvm_exit_reason_offset(kvm_run_ptr: u64) -> u64 {
    let offset = offset_of!(kvm_run, exit_reason);
    kvm_run_ptr + offset as u64
}