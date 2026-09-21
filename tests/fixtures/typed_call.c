#include <stdint.h>

__attribute__((noinline)) uint64_t hydir_call_leaf(uint64_t value) {
    return value ^ UINT64_C(0x9e3779b97f4a7c15);
}

uint64_t hydir_call_wrapper(uint64_t value) {
    return hydir_call_leaf(value) + UINT64_C(7);
}
