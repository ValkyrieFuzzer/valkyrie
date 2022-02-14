/*
  test:
  memcmp function.
*/

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int main(int argc, char **argv) {
  if (argc < 2) return 0;

  FILE *fp;
  char buf[2048];
  size_t ret;

  fp = fopen(argv[1], "rb");
  if (!fp) {
    printf("st err\n");
    return 0;
  }
  int len = 16;
  ret = fread(buf, sizeof *buf, len, fp);
  fclose(fp);
  if (ret < len) {
    printf("input fail \n");
    return 0;
  }

  char *a;
  int c;

  uint32_t size = *(uint32_t *)(buf + 0) + 1;
  printf("size: %d\n", size);
  char *buffer = (char *)malloc(size);
  free(buffer);

  size = *(uint32_t *)(buf + 0) - 1;
  printf("size: %d\n", size);
  buffer = (char *)malloc(size);
  free(buffer);

  size = *(uint32_t *)(buf + 0);
  if (size < 48) {
    return 0;
  }
  printf("size: %d\n", size);
  buffer = (char *)malloc(size - 16 - 32 - 5);

  return 0;
}
