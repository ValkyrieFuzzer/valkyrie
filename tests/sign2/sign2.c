/*
  Test:
  to verify that the sign of y is neg.
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
  int32_t x =
      (getc(fp) << 0) + (getc(fp) << 8) + (getc(fp) << 16) + (getc(fp) << 24);
  int len = fread(buf, 1, 11, fp);
  int32_t y = (buf[3] << 24) + (buf[5] << 16) + (buf[7] << 8) + buf[9];
  int32_t z = *(int32_t *)(buf);
  int32_t w = (buf[7] << 8) + buf[10];
  fclose(fp);

  printf("x: %d, y: %d, z: %d, w: %d\n", x, y, z, w);

  if (x + 32 == -32) {
    printf("hey, you hit it \n");
    abort();
  }
  if (y + 42 == -42) {
    printf("hey, you hit it \n");
    abort();
  }
  if (z - 12 == -120) {
    printf("hey, you hit it \n");
    abort();
  }
  if (w - 8 == -80) {
    printf("hey, you hit it \n");
    abort();
  }
  return 0;
}
