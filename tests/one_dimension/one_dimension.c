/*
  Test:
  Simple `if` conditional statement.
  its both side are variable influenced by the input.
*/
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int main(int argc, char **argv) {
  if (argc < 2) return 0;

  FILE *fp;
  char buf[255];
  size_t ret;

  fp = fopen(argv[1], "rb");

  if (!fp) {
    printf("st err\n");
    return 0;
  }
  uint32_t x = ((uint32_t)getc(fp) << 24) + ((uint32_t)getc(fp) << 16) +
               ((uint32_t)getc(fp) << 8) + getc(fp);
  uint16_t z = (uint32_t)getc(fp);

  fclose(fp);

  if (z >= 2) {
    return 0;
  }
  uint64_t w = (uint64_t)x + ((z) ? 6 : 0);
  printf("x = %d, z = %d, w = %d\n", x, z, w);
  if (w * 3 == 0xffffffff) {
    printf("hey, you hit it \n");
    abort();
  }
  return 0;
}
