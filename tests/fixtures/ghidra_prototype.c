struct Node { int value; struct Node *next; };
__attribute__((noinline)) int walk(struct Node *node, int scale) {
    int total = 0;
    for (; node; node = node->next) total += node->value * scale;
    return total;
}
void _start(void) {
    struct Node last = {3, 0};
    struct Node first = {2, &last};
    volatile int result = walk(&first, 4);
    (void)result;
    for (;;) { }
}
