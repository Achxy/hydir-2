/* Trusted, well-defined C functions for measuring compiler-output coverage. */
#include <stdint.h>

__attribute__((noinline)) uint64_t hydir_opt_identity(uint64_t a, uint64_t b) {
    (void)b;
    return a;
}

__attribute__((noinline)) uint64_t hydir_opt_add(uint64_t a, uint64_t b) {
    return a + b;
}

__attribute__((noinline)) uint64_t hydir_opt_max(uint64_t a, uint64_t b) {
    return a >= b ? a : b;
}

__attribute__((noinline)) uint64_t hydir_opt_xor(uint64_t a, uint64_t b) {
    return a ^ b;
}
