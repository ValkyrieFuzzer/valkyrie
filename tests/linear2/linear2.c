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

  int len = 20;

  ret = fread(buf, sizeof *buf, len, fp);
  fclose(fp);
  if (ret < len) {
    printf("input fail \n");
    return 0;
  }

  int32_t x = 0;
  int32_t y = 0;
  int32_t z = 0;
  int32_t w = 0;
  int32_t t = 0;

  memcpy(&x, buf + 0, 4);   // x 0 - 1
  memcpy(&y, buf + 4, 4);   // x 0 - 1
  memcpy(&z, buf + 8, 4);   // x 0 - 1
  memcpy(&w, buf + 12, 4);  // x 0 - 1
  memcpy(&t, buf + 16, 4);  // x 0 - 1

  if (-3 * x - 7 * y - 6 * z - w - 12 * t == 42) {
    printf("hey, you hit it \n");
    abort();
  }
  return 0;
}
