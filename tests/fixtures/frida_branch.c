#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int hydir_left(int value) { return value + 1; }
__attribute__((noinline)) int hydir_right(int value) { return value + 2; }

__attribute__((noinline)) int hydir_select(int value) {
  int (*volatile target)(int) = value & 1 ? hydir_right : hydir_left;
  return target(value);
}

int main(int argc, char **argv) {
  if (argc != 2) return 64;
  printf("%d\n", hydir_select(atoi(argv[1])));
  return 0;
}
