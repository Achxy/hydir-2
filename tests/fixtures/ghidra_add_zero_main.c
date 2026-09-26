/* Native execution oracle for the real Ghidra raw-P-code rewrite fixture. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern uint64_t hydir_add_zero(uint64_t value);

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    uint64_t value = strtoull(argv[1], 0, 10);
    printf("%llu\n", (unsigned long long)hydir_add_zero(value));
    return 0;
}
