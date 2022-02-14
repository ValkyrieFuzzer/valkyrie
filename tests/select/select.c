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

  return 0;
}
