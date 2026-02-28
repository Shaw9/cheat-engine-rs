mod core;
mod tui;
mod cli;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum Command {
    /// Run in TUI mode (default)
    Tui,
    /// Run in CLI mode
    Cli {
        #[command(subcommand)]
        command: cli::Commands,
    },
}

fn main() {
    let command = Command::parse();

    match command {
        Command::Tui => {
            if let Err(e) = tui::run() {
                panic!("{}", e);
            }
        }
        Command::Cli { command: cli_command } => {
            // Call the corresponding CLI function based on the command
            match cli_command {
                cli::Commands::ListProcesses => {
                    if let Err(e) = cli::list_processes() {
                        panic!("{}", e);
                    }
                }
                cli::Commands::Scan { pid, value, r#type, start, end } => {
                    if let Err(e) = cli::scan_memory(pid, &value, &r#type, start.as_deref(), end.as_deref()) {
                        panic!("{}", e);
                    }
                }
                cli::Commands::Read { pid, address, r#type, size } => {
                    if let Err(e) = cli::read_memory(pid, &address, &r#type, size) {
                        panic!("{}", e);
                    }
                }
                cli::Commands::Write { pid, address, value, r#type } => {
                    if let Err(e) = cli::write_memory(pid, &address, &value, &r#type) {
                        panic!("{}", e);
                    }
                }
            }
        }
    }
}

