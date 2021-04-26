
#ifndef V_V_TYPES_H
#define V_V_TYPES_H

enum v_bool { v_false, v_true };
enum V_ENCRYPT_RESULT {
    SUCCESS,
    OUT_NULL_POINTER,
    WRONG_SIZE_KEY,
    KEY_NULL,
    DATA_NULL,
    ECB_ALIGMENT_ISSUE
};

#endif
