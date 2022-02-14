/*
  Test:
  If we can infer endianess.
*/
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define get_be_32(fp)                                       \
  (((uint32_t)getc(fp) << 24) |                             \
   ((uint32_t)getc(fp) << 16) + ((uint32_t)getc(fp) << 8) | \
   ((uint32_t)getc(fp) << 0))

#define get_le_32(fp)                                      \
  (((uint32_t)getc(fp) << 0) | ((uint32_t)getc(fp) << 8) | \
   ((uint32_t)getc(fp) << 16) | ((uint32_t)getc(fp) << 24))

#define get_split_32(fp)                                    \
  (((uint32_t)getc(fp) << 0) | ((uint32_t)getc(fp) << 16) | \
   ((uint32_t)getc(fp) << 8) | ((uint32_t)getc(fp) << 24))

#define get_be_16(fp) (((uint32_t)getc(fp) << 8) | ((uint32_t)getc(fp) << 0))
#define get_le_16(fp) (((uint32_t)getc(fp) << 0) | ((uint32_t)getc(fp) << 8))

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
  int32_t x = (int32_t)get_be_32(fp) + 21;
  uint32_t y = (uint32_t)get_split_32(fp);
  int32_t z = (int32_t)get_le_16(fp) + 77;

  fclose(fp);

  if (x == 42) {
    printf("hey, you hit it \n");
    abort();
  }

  if (x == -78) {
    printf("hey, you hit it \n");
    abort();
  }

  if (y == 0xdeadbeef) {
    printf("hey, you hit it \n");
    abort();
  }

  if (z == 0x1234) {
    printf("hey, you hit it \n");
    abort();
  }
  return 0;
}
