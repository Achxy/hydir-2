/* Trusted oracle CLI. HYDIR_FUNCTION is selected by the build script. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef HYDIR_FUNCTION
#error "HYDIR_FUNCTION must name the trusted fixture"
#endif

extern uint64_t HYDIR_FUNCTION(uint64_t, uint64_t);

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    uint64_t a = strtoull(argv[1], 0, 10);
    uint64_t b = strtoull(argv[2], 0, 10);
    printf("%llu\n", (unsigned long long)HYDIR_FUNCTION(a, b));
    return 0;
}
