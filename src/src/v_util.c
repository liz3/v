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
    }
    return "undefined result enum type provided";
}

void v_dataToIntArray(uint8_t* dataIn, uint32_t* outp, size_t counter) {
    for (size_t i = 0; i < counter; i++) {
        *(outp + i) = *(((uint32_t*)dataIn) + i);
    }
}

void v_copy(uint8_t* src, uint8_t* target, size_t targetOffset,
            size_t sourceStart, size_t amount) {
    for (size_t i = 0; i < amount; i++) {
        target[i + targetOffset] = src[sourceStart + i];
    }
}