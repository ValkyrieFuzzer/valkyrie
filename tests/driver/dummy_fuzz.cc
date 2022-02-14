#include "dummy.h"
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"

extern "C" {
int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  if (size < 10) {
    return 0;
  }

  int a = ptr_to_int_1(data);
  int b = ptr_to_int_2(data, size);
  printf("a: %d, b: %d\n", a, b);

  return 0;
}
}