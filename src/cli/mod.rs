use clap::Parser;
use std::error::Error;

use crate::core::scan::{Scan, ValueType};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Command to execute
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Parser, Debug)]
pub enum Commands {
    /// List running processes
    ListProcesses,
    /// Scan memory for a value
    Scan {
        /// Process ID
        #[arg(short, long)]
        pid: u32,
        /// Value to search for
        #[arg(short, long)]
        value: String,
        /// Value type (u32, i32, u64, i64, string, hex)
        #[arg(short, long, default_value = "u32")]
        r#type: String,
        /// Start address (hex)
        #[arg(short, long)]
        start: Option<String>,
        /// End address (hex)
        #[arg(short, long)]
        end: Option<String>,
    },
    /// Read memory at a specific address
    Read {
        /// Process ID
        #[arg(short, long)]
        pid: u32,
        /// Address to read from (hex)
        #[arg(short, long)]
        address: String,
        /// Value type (u32, i32, u64, i64, string, hex)
        #[arg(short, long, default_value = "u32")]
        r#type: String,
        /// Read size (for string/hex types)
        #[arg(short, long)]
        size: Option<usize>,
    },
    /// Write memory at a specific address
    Write {
        /// Process ID
        #[arg(short, long)]
        pid: u32,
        /// Address to write to (hex)
        #[arg(short, long)]
        address: String,
        /// Value to write
        #[arg(short, long)]
        value: String,
        /// Value type (u32, i32, u64, i64, string, hex)
        #[arg(short, long, default_value = "u32")]
        r#type: String,
    },
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ListProcesses => list_processes()?,
        Commands::Scan { pid, value, r#type, start, end } => {
            scan_memory(pid, &value, &r#type, start.as_deref(), end.as_deref())?
        }
        Commands::Read { pid, address, r#type, size } => {
            read_memory(pid, &address, &r#type, size)?
        }
        Commands::Write { pid, address, value, r#type } => {
            write_memory(pid, &address, &value, &r#type)?
        }
    }

    Ok(())
}

pub fn list_processes() -> Result<(), Box<dyn Error>> {
    use sysinfo::{Process, System};

    let mut system = System::new_all();
    system.refresh_all();

    println!("{:<10} {:<20} {:<10}", "PID", "Name", "Status");
    println!("{:-<10} {:-<20} {:-<10}", "", "", "");

    for (pid, process) in system.processes() {
        println!("{:<10} {:<20} {:<10}", pid, process.name().to_string_lossy(), process.status());
    }

    Ok(())
}

fn parse_address(addr_str: Option<&str>) -> Result<Option<u64>, Box<dyn Error>> {
    match addr_str {
        Some(addr) => {
            let addr = addr.trim_start_matches("0x");
            let addr = u64::from_str_radix(addr, 16)?;
            Ok(Some(addr))
        }
        None => Ok(None),
    }
}

fn parse_value_type(type_str: &str) -> Result<ValueType, Box<dyn Error>> {
    match type_str.to_lowercase().as_str() {
        "u32" => Ok(ValueType::U32),
        "i32" => Ok(ValueType::I32),
        "u64" => Ok(ValueType::U64),
        "i64" => Ok(ValueType::I64),
        "string" => Ok(ValueType::String),
        "hex" => Ok(ValueType::Hex),
        _ => Err("Invalid value type".into()),
    }
}

pub fn scan_memory(
    pid: u32,
    value: &str,
    type_str: &str,
    start_str: Option<&str>,
    end_str: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let value_type = parse_value_type(type_str)?;
    let start = parse_address(start_str)?;
    let end = parse_address(end_str)?;

    let mut scan = Scan::new(pid, vec![], value_type, start, end, None)?;
    scan.set_value_from_str(value)?;

    println!("Scanning process {} for value '{}' (type: {})...", pid, value, type_str);
    let results = scan.init()?;

    println!("Found {} matches:", results.len());
    println!("{:<20} {:<10} {:<10} {:<}", "Address", "Type", "Perms", "Value");
    println!("{:-<20} {:-<10} {:-<10} {:-<}", "", "", "", "");

    for result in results {
        let value_str = result.get_string()?;
        let perms_str = result
            .perms
            .iter()
            .map(|p| match p {
                crate::core::mem::MemoryRegionPerms::Read => "R",
                crate::core::mem::MemoryRegionPerms::Write => "W",
            })
            .collect::<String>();

        println!("0x{:<18} {:<10} {:<10} {:<}", result.address, type_str, perms_str, value_str);
    }

    Ok(())
}

pub fn read_memory(
    pid: u32,
    address_str: &str,
    type_str: &str,
    size: Option<usize>,
) -> Result<(), Box<dyn Error>> {
    use crate::core::mem::read_memory_address;

    let address = u64::from_str_radix(address_str.trim_start_matches("0x"), 16)?;
    let value_type = parse_value_type(type_str)?;

    let read_size = size.unwrap_or_else(|| match value_type {
        ValueType::U64 | ValueType::I64 => 8,
        ValueType::U32 | ValueType::I32 => 4,
        ValueType::String | ValueType::Hex => 32,
    });

    println!("Reading {} bytes from address 0x{} in process {}...", read_size, address_str, pid);
    let value = read_memory_address(pid, address as usize, read_size)?;

    let value_str = value_type.get_value_string(&value)?;
    println!("Value: {}", value_str);

    Ok(())
}

pub fn write_memory(
    pid: u32,
    address_str: &str,
    value: &str,
    type_str: &str,
) -> Result<(), Box<dyn Error>> {
    use crate::core::mem::write_memory_address;

    let address = u64::from_str_radix(address_str.trim_start_matches("0x"), 16)?;
    let value_type = parse_value_type(type_str)?;

    let mut scan = Scan::new(pid, vec![], value_type, None, None, None)?;
    let value_bytes = scan.value_from_str(value)?;

    println!("Writing value '{}' to address 0x{} in process {}...", value, address_str, pid);
    write_memory_address(pid, address as usize, &value_bytes)?;

    println!("Write successful!");

    Ok(())
}
