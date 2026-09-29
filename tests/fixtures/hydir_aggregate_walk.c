/* Independent aggregate and pointer-traversal fixture for the Ghidra lift. */
struct Node {
    int value;
    struct Node *next;
};

typedef unsigned long u64;
struct Node64 {
    u64 value;
    struct Node64 *next;
};

__attribute__((noinline, used))
int hydir_walk_nodes(const struct Node *node, int scale) {
    int total = 0;
    while (node != 0) {
        total += node->value * scale;
        node = node->next;
    }
    return total;
}

__attribute__((noinline, used))
u64 hydir_walk_nodes64(const struct Node64 *node, u64 scale) {
    u64 total = 0;
    while (node != 0) {
        total += node->value * scale;
        node = node->next;
    }
    return total;
}

void _start(void) {
    __asm__ volatile("syscall" : : "a"(60UL), "D"(0UL) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
