#include "dummy.h"

using namespace std;

int ptr_to_int_1(uint8_t *data) {
  int a = *(uint32_t *)(data + 1);
  int b = *(uint32_t *)(data + 5);

  if (a > b) {
    abort();
  }
  return a;
}

int ptr_to_int_2(uint8_t *data, size_t size) {
  // Test if it still works when converted to vector
  vector<uint8_t> vec(data, data + size);
  int c = *(uint32_t *)(vec.data() + 5);
  int d = vec[7];

  if (c > d) {
    abort();
  }
  return c;
}

uint8_t *dummy_read_data(FILE *f, size_t *size) {
  if (!f) {
    return nullptr;
  }
  fseek(f, 0, SEEK_END);
  size_t length = ftell(f);
  fseek(f, 0, SEEK_SET);
  printf("Reading %lu bytes\n", length);
  // Allocate exactly length bytes so that we reliably catch buffer overflows
  uint8_t *bytes = (uint8_t *)malloc(length);
  size_t n_read = fread(bytes, 1, length, f);
  *size = length;
  return bytes;
}

void dummy_free_data(uint8_t *data) { free(data); }