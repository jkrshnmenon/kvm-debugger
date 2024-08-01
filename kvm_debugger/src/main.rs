mod kvm;
mod utils;
mod ptrace;
mod debugger;

use clap::Parser;
use pretty_env_logger;
use debugger::{start_debugger, Args};

fn main() {
    pretty_env_logger::init();
    let args = Args::parse();
    start_debugger(args);
}
