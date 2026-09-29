#include <stdint.h>

struct hydir_chain_pair {
    uint64_t left;
    uint64_t right;
};

__attribute__((noinline)) uint64_t hydir_chain_right(const struct hydir_chain_pair *pair) {
    return pair->right;
}

__attribute__((noinline)) uint64_t hydir_chain_sum(const struct hydir_chain_pair *pair) {
    uint64_t left = pair->left;
    return left + hydir_chain_right(pair);
}
