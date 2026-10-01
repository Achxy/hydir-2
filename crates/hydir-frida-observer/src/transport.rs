//! Bounded, binary-safe stdin transport for the managed Linux worker.
//! No Windows paths, shell strings, or host mounts cross the worker boundary.

use hydir_execution::MAX_INPUT_SPEC_BYTES;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const PROTOCOL_VERSION: u32 = 1;
pub const FRIDA_VERSION: &str = "17.9.5";
pub const MAX_WORKER_ELF_BYTES: usize = 64 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"HYDFRDA1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub ready: bool,
    pub mode: String,
    pub installed: bool,
    pub can_install: bool,
    pub detail: String,
}

pub struct Request {
    pub elf: Vec<u8>,
    pub input: Vec<u8>,
    pub function: u64,
}

pub fn write_request(
    mut output: impl Write,
    elf: &[u8],
    input: &[u8],
    function: u64,
) -> Result<(), String> {
    check_lengths(elf.len() as u64, input.len() as u64)?;
    output
        .write_all(MAGIC)
        .and_then(|()| output.write_all(&(elf.len() as u64).to_le_bytes()))
        .and_then(|()| output.write_all(&(input.len() as u64).to_le_bytes()))
        .and_then(|()| output.write_all(&function.to_le_bytes()))
        .and_then(|()| output.write_all(elf))
        .and_then(|()| output.write_all(input))
        .map_err(|error| error.to_string())
}

fn check_lengths(elf: u64, input: u64) -> Result<(), String> {
    if elf == 0
        || elf > MAX_WORKER_ELF_BYTES as u64
        || input == 0
        || input > MAX_INPUT_SPEC_BYTES as u64
    {
        return Err("Frida worker request exceeds its ELF/InputSpec limits".into());
    }
    Ok(())
}

pub fn read_request(mut input: impl Read) -> Result<Request, String> {
    let mut header = [0; 32];
    input
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if &header[..8] != MAGIC {
        return Err("Unsupported Frida worker request protocol".into());
    }
    let elf_len = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let input_len = u64::from_le_bytes(header[16..24].try_into().unwrap());
    check_lengths(elf_len, input_len)?;
    let mut request = Request {
        elf: vec![0; elf_len as usize],
        input: vec![0; input_len as usize],
        function: u64::from_le_bytes(header[24..32].try_into().unwrap()),
    };
    input
        .read_exact(&mut request.elf)
        .and_then(|()| input.read_exact(&mut request.input))
        .map_err(|error| error.to_string())?;
    if input.read(&mut [0]).map_err(|error| error.to_string())? != 0 {
        return Err("Trailing bytes in Frida worker request".into());
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_frame_round_trip_and_fail_closed() {
        let mut bytes = Vec::new();
        write_request(&mut bytes, b"\x7fELF\x00\xff\r\n", b"{}", 0x20137c).unwrap();
        let request = read_request(bytes.as_slice()).unwrap();
        assert_eq!(request.elf, b"\x7fELF\x00\xff\r\n");
        assert_eq!(request.input, b"{}");
        assert_eq!(request.function, 0x20137c);
        assert!(read_request(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(read_request(extra.as_slice()).is_err());
        bytes[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(read_request(bytes.as_slice()).is_err());
        bytes[0] = 0;
        assert!(read_request(bytes.as_slice()).is_err());
    }
}
