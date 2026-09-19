#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 1024 * 1024 {
        let _ = hydir_backend::import_elf(bytes);
        let _ = hydir_backend::disassemble_elf(bytes);
        let _ = hydir_backend::region_contract(bytes, "hydir_frame_balance");
        let _ = hydir_backend::region_contract(bytes, "hydir_stack_branch");
    }
});
