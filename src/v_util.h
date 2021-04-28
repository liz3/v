#ifndef V_V_UTIL_H
#define V_V_UTIL_H
#ifdef __cplusplus
extern "C" {
#endif

#include "v_types.h"
#include <stdlib.h>
#ifdef __linux__
#include <stdint.h>
#endif

const char* v_get_error_readable(enum V_ENCRYPT_RESULT value);

void v_dataToIntArray(uint8_t* dataIn, uint32_t* outp, size_t counter);

void v_copy(uint8_t* src, uint8_t* target, size_t targetOffset,
            size_t sourceStart, size_t amount);

uint32_t v_swap32(uint32_t val);

size_t v_strlen(char* data);

#ifdef __cplusplus
}
#endif

#endif
