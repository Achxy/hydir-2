#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if !bytes.is_empty() && bytes.len() <= 4096 {
        let _ = hydir_backend::lift_cfg(bytes, 0x1000);
    }
});
