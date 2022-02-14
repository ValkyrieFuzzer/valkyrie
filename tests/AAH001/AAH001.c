#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"

#define PNG_UINT_32_MAX 4294967295
#define PNG_UINT_31_MAX 2147483647

typedef uint32_t png_uint_32;
typedef unsigned char png_byte;
typedef unsigned char* png_const_bytep;

// png.h
/* These describe the color_type field in png_info. */
/* color type masks */
#define PNG_COLOR_MASK_PALETTE 1
#define PNG_COLOR_MASK_COLOR 2
#define PNG_COLOR_MASK_ALPHA 4

/* color types.  Note that not all combinations are legal */
#define PNG_COLOR_TYPE_GRAY 0
#define PNG_COLOR_TYPE_PALETTE (PNG_COLOR_MASK_COLOR | PNG_COLOR_MASK_PALETTE)
#define PNG_COLOR_TYPE_RGB (PNG_COLOR_MASK_COLOR)
#define PNG_COLOR_TYPE_RGB_ALPHA (PNG_COLOR_MASK_COLOR | PNG_COLOR_MASK_ALPHA)
#define PNG_COLOR_TYPE_GRAY_ALPHA (PNG_COLOR_MASK_ALPHA)

#define png_get_uint_32(buf)                                             \
  (((png_uint_32)(*(buf)) << 24) + ((png_uint_32)(*((buf) + 1)) << 16) + \
   ((png_uint_32)(*((buf) + 2)) << 8) + ((png_uint_32)(*((buf) + 3) << 0)))

// pngrutil.c
png_uint_32 png_get_uint_31(png_const_bytep buf) {
  png_uint_32 uval = png_get_uint_32(buf);
  if (uval > PNG_UINT_31_MAX) {
    exit(0);
  };
  return (uval);
}

int main(int argc, char** argv) {
  if (argc < 2) return 0;

  FILE* fp;

  fp = fopen(argv[1], "rb");

  if (!fp) {
    printf("st err\n");
    return 0;
  }
  png_byte buf[13];
  fread(buf, 13, 1, fp);
  fclose(fp);

  // png_handle_IHDR
  png_uint_32 width, height;
  png_byte bit_depth, color_type, compression_type, filter_type;
  png_byte interlaced, channels;
  width = png_get_uint_31(buf);
  height = png_get_uint_31(buf + 4);
  bit_depth = buf[8];
  color_type = buf[9];
  compression_type = buf[10];
  filter_type = buf[11];
  interlaced = buf[12];
  switch (color_type) {
    default: /* invalid, png_set_IHDR calls png_error */
    case PNG_COLOR_TYPE_GRAY:
    case PNG_COLOR_TYPE_PALETTE:
      channels = 1;
      break;
    case PNG_COLOR_TYPE_RGB:
      channels = 3;
      break;
    case PNG_COLOR_TYPE_GRAY_ALPHA:
      channels = 2;
      break;
    case PNG_COLOR_TYPE_RGB_ALPHA:
      channels = 4;
      break;
  }

  // png_check_IHDR
  if (interlaced >= 2) {
    return 0;
  }
  if (height == 0) {
    return 0;
  }
  if (height > PNG_UINT_31_MAX || width > PNG_UINT_31_MAX) {
    return 0;
  }
  if (bit_depth != 1 && bit_depth != 2 && bit_depth != 4 && bit_depth != 8 &&
      bit_depth != 16) {
    return 0;
  }
  if (((color_type == PNG_COLOR_TYPE_PALETTE) && bit_depth > 8) ||
      ((color_type == PNG_COLOR_TYPE_RGB ||
        color_type == PNG_COLOR_TYPE_GRAY_ALPHA ||
        color_type == PNG_COLOR_TYPE_RGB_ALPHA) &&
       bit_depth < 8)) {
    return 0;
  }

  // png_check_chunk_length
  size_t row_factor_l =
      (size_t)width * (size_t)channels * (bit_depth > 8 ? 2 : 1) + 1 +
      (interlaced ? 6 : 0);

  size_t row_factor = (png_uint_32)row_factor_l;

  if (height > PNG_UINT_32_MAX / row_factor) {
    printf("true");
  } else {
    printf("false");
  }

  return 0;
}