/*
  Test:
  Loops
*/

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int __attribute__((noinline)) bar(uint16_t x, uint16_t y) {
  if (x == y * y + 23) {
    return 1;
  } else {
    return 0;
  }
}

int foo1(uint16_t *arr) {
  for (int i = 0; i < arr[0]; i++) {
    printf(" ");
    if (arr[1] == 42) {
      printf(" ");
    } else {
      printf(" ");
    }
  }
}

int foo2(uint16_t *arr) {
  for (int i = 0; i < arr[0]; i++) {
    for (int j = 0; j < arr[1]; j++) {
      printf(" ");
    }

    for (int j = 0; j < arr[2]; j++) {
      printf(" ");
      if (arr[3] == 42) {
        continue;
      } else {
        printf(" ");
      }
    }
  }
}

int foo3(uint16_t *arr) {
  switch (arr[0]) {
    case 3:
      printf(" ");
      break;
    case 6:
      printf(" ");
      break;
    case 7:
      printf(" ");
      break;
    case 9:
      printf(" ");
      break;
    default:
      printf(" ");
      break;
  };

  while (arr[2] > 0) {
    arr[2]--;
    switch (arr[0]) {
      case 3:
        printf(" ");
        break;
      case 9:
        printf(" ");
        continue;
      default:
        printf(" ");
        break;
    };
    for (int i = 0; i < arr[3]; i++) {
      printf(" ");
    }
  }
}

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

  uint16_t a[4];
  memcpy(&a[0], buf, 2);
  memcpy(&a[1], buf + 4, 2);
  memcpy(&a[2], buf + 10, 2);
  memcpy(&a[3], buf + 15, 2);

  for (int i = 0; i < a[0]; i++) {
    if (!bar(a[i], i)) {
      break;
    }
    if (a[2] == 42) {
      continue;
    }

    if (i == 3) {
      abort();
    }
  }

  foo1(a);
  foo2(a);
  foo3(a);
  return 0;
}
