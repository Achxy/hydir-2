/* Independent aggregate and pointer-traversal fixture for the Ghidra lift. */
struct Node {
    int value;
    struct Node *next;
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

void _start(void) {
    __asm__ volatile("syscall" : : "a"(60UL), "D"(0UL) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
