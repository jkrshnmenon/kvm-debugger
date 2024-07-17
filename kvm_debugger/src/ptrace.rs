use libc;
use std::{ptr, process};

pub fn enable_tracing() {
    unsafe {
        if libc::ptrace(
            libc::PTRACE_TRACEME, 
            0, 
            ptr::null_mut::<libc::c_void>(), 
            ptr::null_mut::<libc::c_void>()) < 0 {
                eprintln!("ptrace(PTRACE_TRACEME) failed!");
                process::exit(1);
            }
    }
    println!("Enabled PTRACE_TRACEME");
}


pub fn set_tracesysgood(pid: i32) {
    unsafe {
        if libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            0,
            libc::PTRACE_O_TRACESYSGOOD) < 0 {
                eprintln!("ptrace(PTRACE_SETOPTIONS) failed!");
                process::exit(1);
            }
    }
    println!("Set PTRACE_SETOPTIONS: PTRACE_O_TRACESYSGOOD");
}