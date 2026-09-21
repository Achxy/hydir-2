#![no_main]

use hydir_decompile::{
    decompile_function_at, discover_functions, lift_machine_function_at, lower_function_ir,
    lower_state_ir,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    // Keep each fuzz iteration bounded below production's independent 64 MiB
    // input ceiling. Exercise no more than four discovered functions.
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return;
    }
    let Ok(index) = discover_functions(bytes) else {
        return;
    };
    for function in index.functions.iter().take(4) {
        if let Ok(machine) = lift_machine_function_at(bytes, function.entry) {
            if let Ok(state) = lower_state_ir(&machine) {
                let _ = lower_function_ir(&machine, &state);
            }
        }
        let _ = decompile_function_at(bytes, function.entry);
    }
});
