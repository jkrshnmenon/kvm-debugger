// For argument parsing
use clap::Parser;

use std::collections::BTreeMap;
use std::process;

use libc;
use kvm_bindings::{
    kvm_guest_debug,
    KVM_GUESTDBG_ENABLE,
    KVM_GUESTDBG_SINGLESTEP,
    KVM_GUESTDBG_USE_SW_BP,
};
use kvm_bindings::bindings::kvm_guest_debug_arch;

use crate::ptrace::{
    enable_tracing, 
    execute_ioctl, 
    finish_syscall, 
    set_tracesysgood, 
    trace_one_syscall, 
    write_proc_memory,
    set_regs
};

use crate::kvm::*;
use crate::utils::bss_addr;

#[derive(Parser, Debug)]
#[command(name = "KVM Debugger", version = "0.1", author = "Jayakrishna Menon <jkrshnmenon@gmail.com>", about = "A debugger of KVM based VMs")]
pub struct Args {
    /// The fixed argument
    pub path: String,

    /// Additional arguments
    pub args: Vec<String>,
}

struct Vm {
    /// The PID of the child process
    pid: libc::pid_t,

    /// The Vcpus for this VM
    vcpus: BTreeMap<u32, u64>
}


struct KvmDebugger {
    /// The arguments for the process to be debugger
    args: Args,

    /// The VM for this debugger
    vm: Vm
}


impl KvmDebugger {
    fn fork_and_exec_vm(&mut self) -> i32 {
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                // Child process
                // Enable tracing using PTRACE_TRACEME
                enable_tracing();

                // Make argv
                let mut args = Vec::<String>::new();
                args.push(self.args.path.clone());
                args.extend(self.args.args.clone().into_iter());

                // Make envp
                let env = std::env::vars().
                map(|(key, val)| format!("{key}={val}"))
                .collect::<String>();

                // Call execve
                libc::execve(
                    args[0].as_str().as_ptr() as *const i8,
                    args.as_ptr() as *const *const i8,
                    env.as_ptr() as *const *const i8,
                );
                process::exit(0);
            } else {
                // Parent process
                // When delivering system call traps, set bit 7 in the
                // signal number (i.e., deliver SIGTRAP|0x80).  This
                // makes it easy for the tracer to distinguish normal
                // traps from those caused by a system call
                set_tracesysgood(pid);
                self.vm.pid = pid;
                pid
            }
        }
    }

    fn add_vcpu(&mut self, vcpu_fd: u32, kvm_run: u64) {
        self.vm.vcpus.insert(vcpu_fd, kvm_run);
    }

    fn check_vcpu(&self, vcpu_fd: u32) -> bool {
        self.vm.vcpus.contains_key(&vcpu_fd)
    }

    fn update_vcpu(&mut self, vcpu_fd: u32, kvm_run: u64) {
        self.vm.vcpus.insert(vcpu_fd, kvm_run);
    }

    fn get_kvm_run(&self, vcpu_fd: u32) -> u64 {
        *self.vm.vcpus.get(&vcpu_fd).unwrap()
    }

    fn setup_kvm_guestdbg(&mut self) {
        let mut enabled = false;
        loop {
            let regs = trace_one_syscall(self.vm.pid);
            match regs.orig_rax as i64 {
                libc::SYS_mmap => {
                    let fd = regs.r8 as u32;
                    let result_regs = finish_syscall(self.vm.pid);
                    if self.check_vcpu(fd) {
                        self.update_vcpu(fd, result_regs.rax);
                    }
                },
                libc::SYS_ioctl => {
                    let fd = regs.rdi as u32;
                    let ioctl = regs.rsi;
                    match ioctl {
                        KVM_CREATE_VCPU => {
                            self.add_vcpu(fd, 0)
                        },
                        KVM_GET_SREGS => {
                            // Set up KVM debug stuff
                            if enabled == false {
                                let vcpu_fd = regs.rdi as u32;
                                let mut result_regs = finish_syscall(self.vm.pid);
                                assert_eq!(result_regs.rax, 0);

                                let saved_regs = result_regs.clone();
                                let dbg: kvm_guest_debug = kvm_guest_debug {
                                    control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_SW_BP,
                                    pad: 0,
                                    arch: kvm_guest_debug_arch {
                                        debugreg: [0; 8]
                                    }
                                };
                                // Convert dbg into a slice of u8
                                let content = unsafe {
                                    std::slice::from_raw_parts(
                                        &dbg as *const kvm_guest_debug as *const u8,
                                        std::mem::size_of::<kvm_guest_debug>()
                                    )
                                };
                                let addr: u64 = bss_addr(self.vm.pid).unwrap() as u64;
                                write_proc_memory(self.vm.pid, addr, content);

                                execute_ioctl(result_regs.rip - 2, self.vm.pid, vcpu_fd as u64, KVM_SET_GUEST_DEBUG, addr, &mut result_regs);

                                set_regs(self.vm.pid, &saved_regs);
                                enabled = true;
                            }
                        },
                        KVM_RUN => {
                            // Do the other thing
                        },
                        _ => {
                            finish_syscall(self.vm.pid);
                        }
                    }
                },
                _ => {
                    _ = finish_syscall(self.vm.pid);
                }
            }
        }
    }
}


pub fn start_debugger(args: Args) {
    let vm = Vm {
        pid: 0,
        vcpus: BTreeMap::new()
    };

    let mut debugger = KvmDebugger {
        args,
        vm
    };

    debugger.fork_and_exec_vm();
    debugger.setup_kvm_guestdbg();
}