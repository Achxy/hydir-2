#ifndef HYDIR_VM_VADD_STATE_H
#define HYDIR_VM_VADD_STATE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t vreg[4];
    uint64_t stack[16];
    uint64_t sp;   /* Index of the next free stack slot. */
    uint64_t vpc;  /* Index of the current one-byte virtual opcode. */
} VMState;

_Static_assert(offsetof(VMState, vreg) == 0, "vreg offset");
_Static_assert(offsetof(VMState, stack) == 32, "stack offset");
_Static_assert(offsetof(VMState, sp) == 160, "sp offset");
_Static_assert(offsetof(VMState, vpc) == 168, "vpc offset");
_Static_assert(sizeof(VMState) == 176, "state size");

#endif
