/* Trusted oracle CLI for the u64(u64,u64) M1 function contract. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern uint64_t hydir_add2(uint64_t, uint64_t);

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    uint64_t a = strtoull(argv[1], 0, 10);
    uint64_t b = strtoull(argv[2], 0, 10);
    printf("%llu\n", (unsigned long long)hydir_add2(a, b));
    return 0;
}
