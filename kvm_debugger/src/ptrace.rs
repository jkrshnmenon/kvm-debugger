use libc;
use std::{process, ptr};

const PRE_SYSCALL: u32 = 0;
const POST_SYSCALL: u32 = 1;

static mut CUR_STATE: u32 = POST_SYSCALL;

pub fn default_regs() -> libc::user_regs_struct {
    libc::user_regs_struct {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        orig_rax: 0,
        rip: 0,
        cs: 0,
        eflags: 0,
        rsp: 0,
        ss: 0,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

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


pub fn trace_one_syscall(pid: i32) -> libc::user_regs_struct {
    unsafe {
        if CUR_STATE != POST_SYSCALL {
            eprintln!("Unexpected state!");
            process::exit(1);
        }
    }
    unsafe {
        if libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>()) < 0 {
                eprintln!("ptrace(PTRACE_SYSCALL) failed!");
                process::exit(1);
            }
    }

    let mut status: i32 = 0;
    unsafe {
        let _ = libc::waitpid(pid, &mut status, 0);
    }

    if status != 0 {
        eprintln!("waitpid failed!");
        process::exit(1);
    }

    unsafe {
        CUR_STATE = PRE_SYSCALL;
    }

    let mut regs: libc::user_regs_struct = default_regs();
    unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut libc::user_regs_struct);
    }
    regs
}

pub fn finish_syscall(pid: i32) -> libc::user_regs_struct {
    unsafe {
        if CUR_STATE != PRE_SYSCALL {
            eprintln!("Unexpected state!");
            process::exit(1);
        }
    }
    unsafe {
        if libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>()) < 0 {
                eprintln!("ptrace(PTRACE_SYSCALL) failed!");
                process::exit(1);
            }
    }

    let mut status: i32 = 0;
    unsafe {
        let _ = libc::waitpid(pid, &mut status, 0);
    }

    if status != 0 {
        eprintln!("waitpid failed!");
        process::exit(1);
    }

    unsafe {
        CUR_STATE = POST_SYSCALL;
    }

    let mut regs: libc::user_regs_struct = default_regs();
    unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut libc::user_regs_struct);
    }
    regs
}


pub fn read_proc_memory(pid: i32, addr: u64, len: usize) -> Vec<u8> {
    let mut content = Vec::<u8>::with_capacity(len);
    for x in (0..len).step_by(8) {
        let mut data: u64 = 0;
        // PEEKDATA reads a long value from the address
        unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKDATA,
                pid,
                addr + x as u64,
                &mut data as *mut u64 as *mut libc::c_void);
        }
        let min = std::cmp::min(8, len - x);
        for j in 0..min {
            content.push(((data >> (j * 8)) & 0xff) as u8);
        }
    }
   content 
}


pub fn write_proc_memory(pid: i32, addr: u64, content: &[u8]) {
    for x in (0..content.len()).step_by(8) {
        let mut data: u64 = 0;
        for j in 0..std::cmp::min(8, content.len() - x) {
            data |= (content[x + j] as u64) << (j * 8);
        }
        // POKEDATA writes a long value to the address
        unsafe {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                addr + x as u64,
                data as *mut u64 as *mut libc::c_void);
        }
    }
}


pub fn set_regs(pid: i32, regs: &libc::user_regs_struct) {
    unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            ptr::null_mut::<libc::c_void>(),
            regs as *const libc::user_regs_struct as *mut libc::user_regs_struct);
    }
}


pub fn execute_ioctl(
    syscall_ins_addr: u64, 
    pid: i32, 
    arg1: u64, 
    arg2: u64, 
    arg3: u64, 
    regs: &mut libc::user_regs_struct) -> u64 {

    regs.rip = syscall_ins_addr;

    let foo: Vec<u8> = read_proc_memory(pid, syscall_ins_addr, 2);
    assert_eq!(foo, vec![0x0f, 0x05]);

    set_regs(pid, regs);

    let mut new_regs = trace_one_syscall(pid);

    new_regs.rax = libc::SYS_ioctl as u64;
    new_regs.rdi = arg1;
    new_regs.rsi = arg2;
    new_regs.rdx = arg3;
    set_regs(pid, &new_regs);

    let result_regs = finish_syscall(pid);
    assert_eq!(result_regs.rax, 0);
    result_regs.rax
}