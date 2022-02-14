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

  fp = fopen(argv[1], "rb");

  if (!fp) {
    printf("st err\n");
    return 0;
  }

  uint32_t len;
  fread(&len, 1, 2, fp);
  // malloc not exploitable
  uint16_t *buf = (uint16_t *)malloc(len * 2);
  fread(buf, 2, len, fp);
  fclose(fp);

  size_t idx = buf[0];
  printf("%d, %d\n", len, idx);
  uint32_t num = *(buf + idx);
  if (num > 4) {
    abort();
  }
  free(buf);

  return 0;
}
