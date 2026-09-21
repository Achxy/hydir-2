#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= 64 * 1024 {
        if let Ok(ir) = std::str::from_utf8(bytes) {
            let _ = hydir_c::emit_structured_c(ir);
        }
    }
});
