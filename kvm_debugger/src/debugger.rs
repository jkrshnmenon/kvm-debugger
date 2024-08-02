#![allow(non_upper_case_globals)]
// For argument parsing
use clap::Parser;
use std::process;
use std::ffi::CString;
use std::collections::BTreeMap;
use libc::{
    SYS_ioctl, 
    SYS_mmap, 
    waitpid, 
    WIFEXITED
};
use kvm_bindings::KVM_EXIT_DEBUG;
use log::{
    trace, 
    info, 
    debug, 
    error
};

use crate::kvm::*;
use crate::ptrace::{
    enable_tracing, 
    execute_ioctl, 
    finish_syscall, 
    read_proc_memory, 
    set_regs, 
    set_tracesysgood, 
    trace_one_syscall, 
    write_proc_memory
};
use crate::utils::{
    bss_addr, 
    syscall_name
};

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
                trace!("Enabling tracing for the child process");
                enable_tracing();

                // Make argv
                let mut c_args: Vec<CString> = Vec::new();
                c_args.push(CString::new(self.args.path.clone()).expect("CString::new failed"));
                c_args.extend(self.args.args.iter().map(|arg| CString::new(arg.clone()).expect("CString::new failed")));

                let mut c_args_ptrs: Vec<*const libc::c_char> = c_args.iter().map(|arg| arg.as_ptr()).collect();
                c_args_ptrs.push(std::ptr::null());

                // Make envp
                let env: Vec<CString> = std::env::vars()
                .map(|(key, val)| CString::new(format!("{key}={val}")).expect("CString::new failed"))
                .collect();

                let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
                env_ptrs.push(std::ptr::null());

                trace!("Calling execve");
                if libc::execve(
                    c_args_ptrs[0],
                    c_args_ptrs.as_ptr(),
                    env_ptrs.as_ptr(),
                ) == -1
                {
                    let err = std::io::Error::last_os_error();
                    eprintln!("Execve failed: {}", err);
                    process::exit(1);
                }

                process::exit(0);
            } else {
                debug!("Got child pid: {}", pid);
                trace!("Enabling TRACESYSGOOD for the child process");
                set_tracesysgood(pid);
                self.vm.pid = pid;
                pid
            }
        }
    }

    fn add_vcpu(&mut self, vcpu_fd: u32, kvm_run: u64) {
        trace!("Adding VCPU: {}", vcpu_fd);
        self.vm.vcpus.insert(vcpu_fd, kvm_run);
    }

    fn check_vcpu(&self, vcpu_fd: u32) -> bool {
        self.vm.vcpus.contains_key(&vcpu_fd)
    }

    fn update_vcpu(&mut self, vcpu_fd: u32, kvm_run: u64) {
        trace!("Updating VCPU: {} with kvm_run: {:#016x}", vcpu_fd, kvm_run);
        self.vm.vcpus.insert(vcpu_fd, kvm_run);
    }

    fn get_kvm_run(&self, vcpu_fd: u32) -> u64 {
        *self.vm.vcpus.get(&vcpu_fd).unwrap()
    }

    fn setup_kvm_guestdbg(&mut self) {
        let mut status = 0;
        unsafe { 
            if waitpid(self.vm.pid, &mut status, 0) == -1 {
                error!("waitpid failed");
            }
        }
        if WIFEXITED(status) {
            error!("Child exited normally with status: {}", WIFEXITED(status));
        }

        let mut enabled = false;
        while enabled == false {

            let regs = trace_one_syscall(self.vm.pid);

            match regs.orig_rax as i64 {
                SYS_mmap => {
                    let fd = regs.r8 as u32;
                    trace!("Mmap syscall: {}", fd);

                    let result_regs = finish_syscall(self.vm.pid);

                    if self.check_vcpu(fd) {
                        self.update_vcpu(fd, result_regs.rax);
                    }
                },
                SYS_ioctl => {
                    let ioctl = regs.rsi;

                    match ioctl {
                        KVM_CREATE_VCPU => {
                            let result_regs = finish_syscall(self.vm.pid);
                            trace!("KVM_CREATE_VCPU ioctl");

                            self.add_vcpu(result_regs.rax as u32, 0)
                        },
                        KVM_GET_SREGS => {
                            // Set up KVM debug stuff
                            if enabled == false {
                                trace!("Enabling KVM_GUESTDBG");
                                let vcpu_fd = regs.rdi as u32;

                                let mut result_regs = finish_syscall(self.vm.pid);
                                assert_eq!(result_regs.rax, 0);
                                debug!("KVM_GET_SREGS success");

                                // Create a copy of the registers
                                let saved_regs = result_regs.clone();

                                let addr: u64 = bss_addr(self.vm.pid).unwrap() as u64;
                                write_proc_memory(self.vm.pid, addr, kvm_guest_debug_obj().as_slice());

                                trace!("Executing KVM_SET_GUEST_DEBUG ioctl on vcpu_fd: {}", vcpu_fd);
                                execute_ioctl(
                                    result_regs.rip - 2, 
                                    self.vm.pid, 
                                    vcpu_fd as u64, 
                                    KVM_SET_GUEST_DEBUG, 
                                    addr, 
                                    &mut result_regs);

                                // Restore the registers
                                set_regs(self.vm.pid, &saved_regs);

                                enabled = true;
                                debug!("KVM_GUESTDBG should now be enabled");
                            }
                        },
                        _ => {
                            trace!("Other ioctl: {:#016x}", ioctl);
                            finish_syscall(self.vm.pid);
                        }
                    }
                },
                _ => {
                    trace!("Other syscall: {} {}", regs.orig_rax, syscall_name(regs.orig_rax as i64));
                    _ = finish_syscall(self.vm.pid);
                }
            }
        }
    }

    fn enable_singlestep(&mut self) {
        let mut enabled = false;
        while enabled == false {
            let regs = trace_one_syscall(self.vm.pid);

            match regs.orig_rax as i64 {
                SYS_ioctl => {
                    let ioctl = regs.rsi;
                    match ioctl {
                        KVM_RUN => {
                            trace!("Enabling single step");
                            let vcpu_fd = regs.rdi as u32;

                            let mut result_regs = finish_syscall(self.vm.pid);
                            let syscall_ins = result_regs.rip - 2;

                            let addr = bss_addr(self.vm.pid).unwrap() as u64;

                            trace!("Calling KVM_GET_REGS");
                            execute_ioctl(
                                syscall_ins,
                                self.vm.pid, 
                                vcpu_fd as u64, 
                                KVM_GET_REGS, 
                                addr, 
                                &mut result_regs);
                            
                            let mut kvm_regs = kvm_regs_from_vec(
                                read_proc_memory(
                                    self.vm.pid, 
                                    addr, 
                                    kvm_regs_size()
                                )
                            );

                            kvm_regs.rflags |= 0x100;

                            write_proc_memory(self.vm.pid, addr, &kvm_regs_to_vec(kvm_regs));

                            trace!("Calling KVM_SET_REGS");
                            execute_ioctl(
                                syscall_ins, 
                                self.vm.pid, 
                                vcpu_fd as u64,
                                KVM_SET_REGS,
                                addr,
                                &mut result_regs);
                            
                            trace!("Calling KVM_RUN");
                            execute_ioctl(
                                syscall_ins, 
                                self.vm.pid, 
                                vcpu_fd as u64,
                                KVM_RUN,
                                0,
                                &mut result_regs);

                            debug!("Single step should now be enabled");
                            let exit_reason_vec = read_proc_memory(
                                self.vm.pid, 
                                kvm_exit_reason_offset(
                                    self.get_kvm_run(vcpu_fd)
                                ), 
                                8
                            );
                            let exit_reason = u64::from_ne_bytes(exit_reason_vec.try_into().unwrap());
                            assert_eq!(exit_reason as u32, KVM_EXIT_DEBUG);
                            info!("SUCCESS");
                            enabled = true;
                        },
                        _ => {
                            trace!("Other ioctl: {:#016x}", ioctl);
                            finish_syscall(self.vm.pid);
                        }
                    }
                },
                _ => {
                    trace!("Other syscall: {} {}", regs.orig_rax, syscall_name(regs.orig_rax as i64));
                    finish_syscall(self.vm.pid);
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

    info!("Forking and executing the VM");
    debugger.fork_and_exec_vm();

    info!("Setting up KVM guest debug");
    debugger.setup_kvm_guestdbg();

    info!("Enabling single step");
    debugger.enable_singlestep();
}