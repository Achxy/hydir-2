/* Independent stripped-binary holdout for the automatic Ghidra/Hydir route.
 *
 * A frame is A7, a payload length of at most 12, payload bytes, then the low
 * byte of a rolling state. Keep the executable freestanding so its native
 * code can be replayed from the exact ELF analyzed by Ghidra.
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;

__attribute__((noinline, used))
u32 hydir_frame_step(u32 state, u8 value, u32 index) {
    state ^= (u32)value + index * 17u;
    state *= 0x01000193u;
    return state ^ (state >> 13);
}

__attribute__((noinline, used))
u32 hydir_frame_accept(const u8 *frame, u64 size) {
    if (size < 3 || frame[0] != 0xa7)
        return 0;
    u32 count = frame[1];
    if (count > 12 || size != (u64)count + 3)
        return 0;
    u32 state = 0xc0de1234u;
    for (u32 index = 0; index < count; ++index)
        state = hydir_frame_step(state, frame[2 + index], index);
    return (u8)state == frame[2 + count];
}

void _start(void) {
    __asm__ volatile("syscall" : : "a"(60UL), "D"(0UL) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
