#ifndef V_V_UTIL_H
#define V_V_UTIL_H

#include "v_types.h"
#include <stdlib.h>

const char* v_get_error_readable(enum V_ENCRYPT_RESULT value);

void v_dataToIntArray(uint8_t* dataIn, uint32_t* outp, size_t counter);

void v_copy(uint8_t* src, uint8_t* target, size_t targetOffset,
            size_t sourceStart, size_t amount);

#endif