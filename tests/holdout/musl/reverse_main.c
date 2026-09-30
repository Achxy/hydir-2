#include <stddef.h>
#include <stdio.h>
#include <string.h>

const char hydir_reverse_word[] = "bananas";

int main(void)
{
    char *last = strrchr(hydir_reverse_word, 'a');
    ptrdiff_t offset = last ? last - hydir_reverse_word : -1;
    printf("%td\n", offset);
    return offset == 5 ? 0 : 1;
}
