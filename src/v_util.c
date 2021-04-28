#include "v_util.h"

const char* v_get_error_readable(enum V_ENCRYPT_RESULT value) {
  switch (value) {
  case SUCCESS:
    return "Successfully encrypted data provided";
  case OUT_NULL_POINTER:
    return "The out argument should be a pointer an uninitialized "
      "pointer * as v will not allocate it, a null pointer was "
      "encountered";
  case ECB_ALIGMENT_ISSUE:
    return "ECB required the payload to be a multiplier of 16";
  case INVALID_MODE:
    return "A invalid operation mode was provided";
    case INVALID_HANDLE:
      return "The AES handle was NULL";
  }
  return "undefined result enum type provided";
}

void v_dataToIntArray(uint8_t* dataIn, uint32_t* outp, size_t counter) {
    for (size_t i = 0; i < counter; i++) {
        *(outp + i) = v_swap32(*(((uint32_t*)dataIn) + i));
    }
}

void v_copy(uint8_t* src, uint8_t* target, size_t targetOffset,
            size_t sourceStart, size_t amount) {
    for (size_t i = 0; i < amount; i++) {
        target[i + targetOffset] = src[sourceStart + i];
    }
}

uint32_t v_swap32(uint32_t val) {
    return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
           ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF);
}

uint8_t* v_safe_allocate(size_t size) {
  uint8_t* p = malloc(size);
  for(size_t i = 0; i < size; i++) {
    p[i] = 0;
  }
  return p;
}

size_t v_strlen(char* data) {
    size_t start = 0;
    while(1) {
        if(data[start] == '\0') break;
        start++;
    }
    return start;
}
