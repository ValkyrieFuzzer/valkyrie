/*
  Test:
  I just want to find the optimizations for switch..
 */
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int main(int argc, char** argv) {
  /***** common part *******/
  int len = 20;
  FILE* fp;
  fp = fopen(argv[1], "rb");
  int b = (getc(fp) << 8) + getc(fp);
  fclose(fp);
  /*************************/

  switch (b) {
    case 1:
      printf("11");
      break;
    case 2:
      printf("22");
      break;

    default:
      printf("123");
      break;
  }
}
