#include <stdint.h>

struct hydir_recursive_node {
    uint64_t value;
    struct hydir_recursive_node *next;
};

__attribute__((noinline)) uint64_t hydir_recursive_sum(const struct hydir_recursive_node *node) {
    if (!node) return 0;
    uint64_t value = node->value;
    return value + hydir_recursive_sum(node->next);
}
