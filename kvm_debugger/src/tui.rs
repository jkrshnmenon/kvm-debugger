use crossterm::{execute, terminal, cursor};

use kvm_bindings::kvm_regs;
use std::io::stdout;

fn color_red(msg: &str) -> String {
    format!("\x1b[31m{}\x1b[0m", msg)
}

fn color_green(msg: &str) -> String {
    format!("\x1b[32m{}\x1b[0m", msg)
}

fn color_blue(msg: &str) -> String {
    format!("\x1b[34m{}\x1b[0m", msg)
}

fn color_yellow(msg: &str) -> String {
    format!("\x1b[33m{}\x1b[0m", msg)
}

fn clear_screen() {
    let mut stdout = stdout();
    execute!(stdout, terminal::Clear(terminal::ClearType::All), cursor::MoveTo(0, 0)).unwrap();
}

fn display_banner() {
    clear_screen();
    let header = "-".repeat(80);
    let title = " ".repeat(20) + "KVM Debugger";
    println!("{}", color_green(format!("{}\n{}\n{}", header, title, header).as_str()));
}

fn display_regs(regs: kvm_regs) {
    println!("{}", color_red(("-".repeat(80) + " registers").as_str()));
    println!("{}", color_red(format!("$rax   : 0x{:x}", regs.rax).as_str()));
    println!("{}", color_red(format!("$rbx   : 0x{:x}", regs.rbx).as_str()));
    println!("{}", color_red(format!("$rcx   : 0x{:x}", regs.rcx).as_str()));
    println!("{}", color_red(format!("$rdx   : 0x{:x}", regs.rdx).as_str()));
    println!("{}", color_red(format!("$rsp   : 0x{:x}", regs.rsp).as_str()));
    println!("{}", color_red(format!("$rbp   : 0x{:x}", regs.rbp).as_str()));
    println!("{}", color_red(format!("$rsi   : 0x{:x}", regs.rsi).as_str()));
    println!("{}", color_red(format!("$rdi   : 0x{:x}", regs.rdi).as_str()));
    println!("{}", color_red(format!("$rip   : 0x{:x}", regs.rip).as_str()));
    println!("{}", color_red(format!("$r8    : 0x{:x}", regs.r8).as_str()));
    println!("{}", color_red(format!("$r9    : 0x{:x}", regs.r9).as_str()));
    println!("{}", color_red(format!("$r10   : 0x{:x}", regs.r10).as_str()));
    println!("{}", color_red(format!("$r11   : 0x{:x}", regs.r11).as_str()));
    println!("{}", color_red(format!("$r12   : 0x{:x}", regs.r12).as_str()));
    println!("{}", color_red(format!("$r13   : 0x{:x}", regs.r13).as_str()));
    println!("{}", color_red(format!("$r14   : 0x{:x}", regs.r14).as_str()));
    println!("{}", color_red(format!("$r15   : 0x{:x}", regs.r15).as_str()));
    // println!("{}", color_red(format!("$eflags: 0x{:x}", regs.eflags).as_str()));
    // println!("{}", color_red(format!("$cs: 0x{:x} $ss: 0x{:x} $ds: 0x{:x} $es: 0x{:x} $fs: 0x{:x} $gs: 0x{:x}", regs.cs, regs.ss, regs.ds, regs.es, regs.fs, regs.gs).as_str()));
}

fn display_stack(rsp_addr: u64, content: Vec<u64>) {
    println!("{}", color_blue(("-".repeat(80) + " stack").as_str()));
    for (i, val) in content.iter().enumerate() {
        let offset = i as u64 * 8;
        let addr = rsp_addr + offset;
        println!("{}", color_blue(format!("{:#016x}|+{:#04x}: {:#016x}", addr, offset, val).as_str()));
    }
}

fn display_code(rip_addr: u64) {
    println!("{}", color_yellow(("-".repeat(80) + " code").as_str()));
    println!("{}", color_yellow(format!("-> {:#016x}: ", rip_addr).as_str()));
}

pub fn display_for_exit_debug(regs: kvm_regs, stack_content: Vec<u64>) {
    display_banner();
    display_regs(regs);
    display_stack(regs.rsp, stack_content);
    display_code(regs.rip);
}

pub fn display_for_exit_io(direction: u8, port: u16, data: Vec<u8>) {
    display_banner();
    println!("{}", color_green(("-".repeat(80) + " I/O").as_str()));
    println!("{}", color_green(format!("Direction: {}", direction).as_str()));
    println!("{}", color_green(format!("Port: {:x}", port).as_str()));
    println!("{}", color_green(format!("Data: {:?}", data).as_str()));
}