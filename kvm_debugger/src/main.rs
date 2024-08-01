mod kvm;
mod utils;
mod ptrace;
mod debugger;

use debugger::{start_debugger, Args};
use clap::Parser;

use pretty_env_logger;

fn main() {
    pretty_env_logger::init();
    let args = Args::parse();
    start_debugger(args);
}
