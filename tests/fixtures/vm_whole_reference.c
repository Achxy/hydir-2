#include <stdint.h>

/* Reference guest behavior for vm_whole.S. Arithmetic is modulo 2^64. */
uint64_t vm_whole_reference(uint64_t input, uint64_t *output) {
    uint64_t acc = 3;
    for (uint64_t counter = 0; counter < input; counter++) {
        acc += 2;
    }
    if (input & 1) {
        acc ^= 0x55;
    } else {
        acc += 7;
    }
    *output = acc;
    return acc + 1;
}
