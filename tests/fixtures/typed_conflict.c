#include <stdint.h>

struct hydir_a { uint64_t x; };
struct hydir_b { uint64_t x; uint64_t y; };
struct hydir_host { uint64_t tag; void *next; };

__attribute__((noinline)) uint64_t hydir_read_a(const struct hydir_a *value) {
    return value->x;
}

__attribute__((noinline)) uint64_t hydir_read_b(const struct hydir_b *value) {
    return value->y;
}

__attribute__((noinline)) uint64_t hydir_conflicting_next(const struct hydir_host *host, int choice) {
    if (choice) return hydir_read_a(host->next);
    return hydir_read_b(host->next);
}
