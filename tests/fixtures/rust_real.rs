#![no_std]

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn hydir_rust_mix(mut value: u64, count: u32) -> u64 {
    for index in 0..count {
        value = value.rotate_left(11) ^ u64::from(index).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    value
}

#[inline(never)]
pub fn hydir_rust_slice_sum(values: &[u64]) -> u64 {
    values
        .iter()
        .copied()
        .fold(0u64, |sum, value| sum.wrapping_add(value))
}
