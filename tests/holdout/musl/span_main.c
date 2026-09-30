#include <stdio.h>
#include <string.h>

const char hydir_span_word[] = "cabbed!";
const char hydir_span_accept[] = "abcde";

int main(void)
{
    size_t length = strspn(hydir_span_word, hydir_span_accept);
    printf("%zu\n", length);
    return length == 6 ? 0 : 1;
}
