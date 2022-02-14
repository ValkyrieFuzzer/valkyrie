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

  int len = 10;

  ret = fread(buf, sizeof *buf, len, fp);
  fclose(fp);
  if (ret < len) {
    printf("input fail \n");
    return 0;
  }

  uint16_t x = *(uint16_t *)(buf + 1);
  uint32_t y = *(uint32_t *)(buf + 4);
  uint64_t z = *(uint64_t *)(buf + 0);

  // Won't overflow cause we didn't instrument
  // u64 upper bound.
  if (z > 0) {
    int c = 8 / (z + 1);
    printf("%d", c);
  }
  return 0;
}
