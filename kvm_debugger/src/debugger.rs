// For argument parsing
use clap::Parser;
use std::collections::BTreeMap;
use std::process;
use libc;

use crate::ptrace::{
    enable_tracing,
    set_tracesysgood,
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
    /// The file descriptor for the VM
    fd: u32,

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
    fn fork_and_exec_vm(&self) -> i32 {
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
                pid
            }
        }
    }

    fn setup_kvm_guestdbg(self) {
        // TODO
    }
}


pub fn start_debugger(args: Args) {
    let vm = Vm {
        fd: 0,
        pid: 0,
        vcpus: BTreeMap::new()
    };

    let debugger = KvmDebugger {
        args,
        vm
    };

    debugger.fork_and_exec_vm();
    debugger.setup_kvm_guestdbg();
}