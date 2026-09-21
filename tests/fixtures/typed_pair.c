#include <stdint.h>

struct hydir_pair {
    uint64_t left;
    uint64_t right;
};

uint64_t hydir_pair_sum(const struct hydir_pair *pair) {
    return pair->left + pair->right;
}

uint64_t hydir_pair_xor(const struct hydir_pair *pair) {
    return pair->left ^ pair->right;
}
