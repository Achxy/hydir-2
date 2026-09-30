#include <stddef.h>

/* Only the musl-internal declaration and alias macro needed by these files. */
void *__memrchr(const void *memory, int character, size_t length);
#define weak_alias(old_symbol, new_symbol)
