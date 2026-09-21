#include <stdint.h>

struct hydir_array_record {
    uint64_t items[3];
    uint64_t tail;
};

uint64_t hydir_array_sum(const struct hydir_array_record *record) {
    return record->items[0] + record->items[1] + record->items[2] + record->tail;
}
