#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int main(int argc, char **argv) {
  if (argc < 2) return 0;

  FILE *fp;
  unsigned char buf[255];
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

  unsigned a;
  switch (buf[0]) {
    default:
      a = 0;
      break;
    case 24:
      a = 4;
      break;
    case 42:
      a = 1;
      break;
  }

  unsigned b = buf[1] + buf[2] + a;

  if (b == 0xff + 0xff + 4) {
    printf("hey, you hit it \n");
    abort();
  }
  return 0;
}
