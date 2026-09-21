#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    // Keep smoke iterations cheap while the production parser independently
    // enforces its 64 MiB interchange ceiling.
    if !bytes.is_empty() && bytes.len() <= 1024 * 1024 {
        let _ = hydir_interchange::SpecificationDocument::decode(bytes);
    }
});
