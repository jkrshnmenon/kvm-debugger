mod debugger;
mod ptrace;

use debugger::{start_debugger, Args};
use clap::Parser;

fn main() {
    let args = Args::parse();
    println!("{:?}: {:?}", args.path, args.args);
    start_debugger(args);
}
