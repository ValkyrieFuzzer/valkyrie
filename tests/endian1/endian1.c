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

  if (getc(fp) == 42) {
    printf("hey, you hit it \n");
  }

  if (x == 42) {
    if (y == 2) {
      printf("y: %d\n", x);
    }
    printf("hey, you hit it \n");
  }

  if (x == -78) {
    if (y == 2) {
      printf("y: %d\n", x);
    }
    printf("hey, you hit it \n");
  }

  if (y == 0xdeadbeef) {
    if (x == 2) {
      printf("x: %d\n", x);
    }
    printf("hey, you hit it \n");
  }

  if (z == 0x1234) {
    if (x == 2) {
      printf("x: %d\n", x);
    }
    printf("hey, you hit it \n");
  }

  return 0;
}
