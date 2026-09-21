#![no_main]

use hydir_core::{DecompilationUnit, validate_decompilation_unit};
use hydir_ir::{
    Cir, FunctionIndex, FunctionIr, MachineFunctionIr, StateFunctionIr, validate_cir,
    validate_function_index, validate_function_ir, validate_machine_function_ir,
    validate_state_function_ir,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return;
    }
    if let Ok(value) = serde_json::from_slice::<FunctionIndex>(bytes) {
        let _ = validate_function_index(&value);
    }
    if let Ok(value) = serde_json::from_slice::<MachineFunctionIr>(bytes) {
        let _ = validate_machine_function_ir(&value);
    }
    if let Ok(value) = serde_json::from_slice::<StateFunctionIr>(bytes) {
        let _ = validate_state_function_ir(&value);
    }
    if let Ok(value) = serde_json::from_slice::<FunctionIr>(bytes) {
        let _ = validate_function_ir(&value);
    }
    if let Ok(value) = serde_json::from_slice::<Cir>(bytes) {
        let _ = validate_cir(&value);
    }
    if let Ok(value) = serde_json::from_slice::<DecompilationUnit>(bytes) {
        let _ = validate_decompilation_unit(&value);
    }
});
