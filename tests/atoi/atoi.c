#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2)
    return 0;

  FILE *fp;
  char buf[255];
  size_t ret;

  fp = fopen(argv[1], "rb");

  if (!fp) {
    return 0;
  }
  int len = 20;
  fgets(buf, len, fp);
  buf[len] = '\0';

  int num = atoi(buf);
  if (num == 0x7eadbeef) {
    printf("hey, you hit it \n");
    abort();
  }

  return 0;
}
