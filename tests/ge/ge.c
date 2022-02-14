/*
  Test:
  Simple `if` conditional statement.
  its both side are variable influenced by the input.
*/
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define get_be_32(fp)                                       \
  (((uint32_t)getc(fp) << 24) |                             \
   ((uint32_t)getc(fp) << 16) + ((uint32_t)getc(fp) << 8) | \
   ((uint32_t)getc(fp) << 0))

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
  int32_t x = get_be_32(fp);
  fclose(fp);

  if (x > 11000 || x < 10000) {
    return 0;
  }
  if (3 * x > 32768) {
    printf("hey, you hit it \n");
    abort();
  }
  return 0;
}
