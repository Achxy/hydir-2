const ELF_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const PF_READ_EXECUTE: u32 = 5;
const MIN_SEGMENT_ALIGNMENT: u64 = 0x1000;
const MAX_SEGMENT_ALIGNMENT: u64 = 0x20_0000;
const MAX_PROGRAM_HEADERS: usize = 128;

pub(crate) struct ExecutableSegment {
    pub content: Vec<u8>,
    pub original_file_size: u64,
    pub original_program_header_offset: u64,
    pub original_program_header_count: u16,
    pub program_header_offset: u64,
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub code_address: u64,
    pub alignment: u64,
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, String> {
    let value = bytes
        .get(at..at + 2)
        .ok_or("ELF header is truncated")?
        .try_into()
        .map_err(|_| "ELF u16 field is malformed")?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, String> {
    let value = bytes
        .get(at..at + 4)
        .ok_or("ELF program header is truncated")?
        .try_into()
        .map_err(|_| "ELF u32 field is malformed")?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, String> {
    let value = bytes
        .get(at..at + 8)
        .ok_or("ELF program header is truncated")?
        .try_into()
        .map_err(|_| "ELF u64 field is malformed")?;
    Ok(u64::from_le_bytes(value))
}

fn write_u16(bytes: &mut [u8], at: usize, value: u16) -> Result<(), String> {
    bytes
        .get_mut(at..at + 2)
        .ok_or("ELF header is truncated")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], at: usize, value: u32) -> Result<(), String> {
    bytes
        .get_mut(at..at + 4)
        .ok_or("ELF program header is truncated")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(bytes: &mut [u8], at: usize, value: u64) -> Result<(), String> {
    bytes
        .get_mut(at..at + 8)
        .ok_or("ELF program header is truncated")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> Result<u64, String> {
    if !alignment.is_power_of_two() {
        return Err("ELF load segment alignment is not a power of two".to_owned());
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| "ELF placement alignment overflows".to_owned())
}

fn program_header_offset(base: usize, index: usize) -> Result<usize, String> {
    index
        .checked_mul(ELF64_PROGRAM_HEADER_SIZE)
        .and_then(|offset| base.checked_add(offset))
        .ok_or_else(|| "ELF program header offset overflows".to_owned())
}

fn make_load_header(
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    alignment: u64,
) -> Result<[u8; ELF64_PROGRAM_HEADER_SIZE], String> {
    let mut header = [0u8; ELF64_PROGRAM_HEADER_SIZE];
    write_u32(&mut header, 0, PT_LOAD)?;
    write_u32(&mut header, 4, PF_READ_EXECUTE)?;
    write_u64(&mut header, 8, file_offset)?;
    write_u64(&mut header, 16, virtual_address)?;
    write_u64(&mut header, 24, virtual_address)?;
    write_u64(&mut header, 32, file_size)?;
    write_u64(&mut header, 40, file_size)?;
    write_u64(&mut header, 48, alignment)?;
    Ok(header)
}

/// Append a page-aligned RX load segment containing a relocated program-header
/// table followed by replacement code. Existing file offsets and virtual
/// addresses remain unchanged; the ELF header points at the copied table.
pub(crate) fn append_executable_segment(
    bytes: &[u8],
    code: &[u8],
) -> Result<ExecutableSegment, String> {
    if code.is_empty() {
        return Err("trampoline replacement code is empty".to_owned());
    }
    if bytes.len() < ELF_HEADER_SIZE
        || bytes.get(..4) != Some(b"\x7fELF")
        || bytes.get(4) != Some(&2)
        || bytes.get(5) != Some(&1)
    {
        return Err("trampoline placement requires ELF64 little-endian input".to_owned());
    }
    if read_u16(bytes, 16)? != 2 || read_u16(bytes, 18)? != 62 {
        return Err("trampoline placement requires an x86-64 executable".to_owned());
    }
    if read_u16(bytes, 52)? as usize != ELF_HEADER_SIZE
        || read_u16(bytes, 54)? as usize != ELF64_PROGRAM_HEADER_SIZE
    {
        return Err("ELF header or program-header entry size is unsupported".to_owned());
    }

    let old_count = read_u16(bytes, 56)? as usize;
    if old_count == 0 || old_count >= MAX_PROGRAM_HEADERS || old_count == u16::MAX as usize {
        return Err("ELF program-header count is unsupported".to_owned());
    }
    let old_table_offset = usize::try_from(read_u64(bytes, 32)?)
        .map_err(|_| "ELF program-header offset is too large")?;
    let old_table_size = old_count
        .checked_mul(ELF64_PROGRAM_HEADER_SIZE)
        .ok_or("ELF program-header table size overflows")?;
    let old_table_end = old_table_offset
        .checked_add(old_table_size)
        .ok_or("ELF program-header table range overflows")?;
    let old_table = bytes
        .get(old_table_offset..old_table_end)
        .ok_or("ELF program-header table is truncated")?;

    let mut last_load_index = None;
    let mut max_load_end = 0u64;
    let mut alignment = MIN_SEGMENT_ALIGNMENT;
    let mut phdr_index = None;
    for index in 0..old_count {
        let at = program_header_offset(old_table_offset, index)?;
        match read_u32(bytes, at)? {
            PT_LOAD => {
                last_load_index = Some(index);
                let virtual_address = read_u64(bytes, at + 16)?;
                let memory_size = read_u64(bytes, at + 40)?;
                max_load_end = max_load_end.max(
                    virtual_address
                        .checked_add(memory_size)
                        .ok_or("ELF load segment address overflows")?,
                );
                let load_alignment = read_u64(bytes, at + 48)?;
                if load_alignment > 1 {
                    if !load_alignment.is_power_of_two() || load_alignment > MAX_SEGMENT_ALIGNMENT {
                        return Err("ELF load segment alignment is unsupported".to_owned());
                    }
                    alignment = alignment.max(load_alignment);
                }
            }
            PT_PHDR if phdr_index.replace(index).is_some() => {
                return Err("ELF contains multiple PT_PHDR entries".to_owned());
            }
            PT_PHDR => {}
            _ => {}
        }
    }
    let last_load_index = last_load_index.ok_or("ELF has no load segment")?;

    let new_count = old_count + 1;
    let new_table_size = new_count
        .checked_mul(ELF64_PROGRAM_HEADER_SIZE)
        .ok_or("new ELF program-header table size overflows")?;
    let code_offset_in_segment = usize::try_from(align_up(new_table_size as u64, 16)?)
        .map_err(|_| "new ELF code offset is too large")?;
    let segment_size = code_offset_in_segment
        .checked_add(code.len())
        .ok_or("new ELF segment size overflows")?;
    let file_offset = align_up(bytes.len() as u64, alignment)?;
    let virtual_address = align_up(max_load_end, alignment)?;
    let code_address = virtual_address
        .checked_add(code_offset_in_segment as u64)
        .ok_or("new ELF code address overflows")?;

    let mut table = Vec::with_capacity(new_table_size);
    let insert_at = last_load_index + 1;
    for index in 0..old_count {
        if index == insert_at {
            table.extend_from_slice(&make_load_header(
                file_offset,
                virtual_address,
                segment_size as u64,
                alignment,
            )?);
        }
        let start = index * ELF64_PROGRAM_HEADER_SIZE;
        table.extend_from_slice(&old_table[start..start + ELF64_PROGRAM_HEADER_SIZE]);
    }
    if insert_at == old_count {
        table.extend_from_slice(&make_load_header(
            file_offset,
            virtual_address,
            segment_size as u64,
            alignment,
        )?);
    }
    if table.len() != new_table_size {
        return Err("new ELF program-header table has the wrong size".to_owned());
    }

    if let Some(old_index) = phdr_index {
        let new_index = old_index + usize::from(insert_at <= old_index);
        let at = new_index * ELF64_PROGRAM_HEADER_SIZE;
        write_u64(&mut table, at + 8, file_offset)?;
        write_u64(&mut table, at + 16, virtual_address)?;
        write_u64(&mut table, at + 24, virtual_address)?;
        write_u64(&mut table, at + 32, new_table_size as u64)?;
        write_u64(&mut table, at + 40, new_table_size as u64)?;
        write_u64(&mut table, at + 48, 8)?;
    }

    let file_offset_usize =
        usize::try_from(file_offset).map_err(|_| "new ELF segment file offset is too large")?;
    let final_size = file_offset_usize
        .checked_add(segment_size)
        .ok_or("new ELF output size overflows")?;
    let mut content = bytes.to_vec();
    content.resize(final_size, 0);
    write_u64(&mut content, 32, file_offset)?;
    write_u16(&mut content, 56, new_count as u16)?;
    content[file_offset_usize..file_offset_usize + table.len()].copy_from_slice(&table);
    let code_file_offset = file_offset_usize + code_offset_in_segment;
    content[code_file_offset..code_file_offset + code.len()].copy_from_slice(code);

    Ok(ExecutableSegment {
        content,
        original_file_size: bytes.len() as u64,
        original_program_header_offset: old_table_offset as u64,
        original_program_header_count: old_count as u16,
        program_header_offset: file_offset,
        file_offset,
        virtual_address,
        file_size: segment_size as u64,
        code_address,
        alignment,
    })
}

pub(crate) fn restore_original_layout(
    content: &mut Vec<u8>,
    expected_program_header_offset: u64,
    original_file_size: u64,
    original_program_header_offset: u64,
    original_program_header_count: u16,
) -> Result<(), String> {
    if read_u64(content, 32)? != expected_program_header_offset {
        return Err("patched ELF program-header offset differs from its manifest".to_owned());
    }
    let original_file_size =
        usize::try_from(original_file_size).map_err(|_| "original ELF file size is too large")?;
    if original_file_size < ELF_HEADER_SIZE || original_file_size > content.len() {
        return Err("original ELF file size is inconsistent with patched bytes".to_owned());
    }
    write_u64(content, 32, original_program_header_offset)?;
    write_u16(content, 56, original_program_header_count)?;
    content.truncate(original_file_size);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::{Object, ObjectSegment};

    #[test]
    fn appended_segment_is_mapped_read_execute_and_keeps_sections() {
        let input = include_bytes!("../../../fuzz/corpus/elf_import/frame.elf");
        let appended = append_executable_segment(input, &[0xc3]).unwrap();
        let original = object::File::parse(input.as_slice()).unwrap();
        let file = object::File::parse(appended.content.as_slice()).unwrap();
        assert_eq!(file.sections().count(), original.sections().count());
        assert!(file.segments().any(|segment| {
            segment.address() == appended.virtual_address
                && segment.file_range().0 == appended.file_offset
                && segment.data().unwrap().last() == Some(&0xc3)
        }));
    }
}
