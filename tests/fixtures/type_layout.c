#include <stdint.h>

struct hydir_node {
    uint64_t data[5];
    struct hydir_node *next;
};

uint64_t hydir_sum_node(const struct hydir_node *node) {
    uint64_t sum = 0;
    for (unsigned i = 0; i < 5; ++i) {
        sum += node->data[i];
    }
    return sum;
}

uint64_t hydir_sum_list(const struct hydir_node *node) {
    uint64_t sum = 0;
    while (node) {
        sum += hydir_sum_node(node);
        node = node->next;
    }
    return sum;
}
