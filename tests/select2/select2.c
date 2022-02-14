/*
  Test:
  Selection
*/
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int main(int argc, char **argv) {
  if (argc < 2) return 0;

  FILE *fp;
  fp = fopen(argv[1], "rb");
  int32_t x = getc(fp);
  fclose(fp);

  int32_t y = (x == 23) ? 0 : 1;
  printf("y = %d", y);

  int32_t z = (x == 32) ? 32 : 12;
  printf("z = %d", z);

  if (x < 42) {
    int32_t a = (x == 13) ? 1 : 6;
    printf("a = %d", a);
    int32_t b = (x == 34) ? 58 : 78;
    printf("b = %d", b);
  }

  int32_t w = (x == 54) ? 1 : 5;
  printf("w = %d", w);

  return 0;
}
