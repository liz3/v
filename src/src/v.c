#include "v.h"

enum V_ENCRYPT_RESULT v_easy_encrypt(uint8_t* key, uint8_t* data, uint32_t len,
                                     uint16_t keyLen, uint8_t* out) {
    return v_aes_encrypt_implicit(key, data, len, keyLen, out, CTR);
}

enum V_ENCRYPT_RESULT v_aes_encrypt_implicit(
    uint8_t* key, uint8_t* data, uint32_t len, uint16_t keyLen, uint8_t* out,
    enum V_AES_OPERATE_MODE operation_mode) {
    // check if out pointer was not allocated by user
    if (out == 0) {
        return OUT_NULL_POINTER;
    }
    if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
        return WRONG_SIZE_KEY;
    }
    if (key == 0) {
        return KEY_NULL;
    }
    if (data == 0) {
        return DATA_NULL;
    }

    v_aes_handle* h = v_aes_setupHandle(key, keyLen);

    if (operation_mode == CTR) {
        enum V_ENCRYPT_RESULT result = v_aes_ctr_perform(h, data, len, out, 1);
        if (result != SUCCESS) {
            free(h);
            return result;
        }
    } else if (operation_mode == ECB) {
        enum V_ENCRYPT_RESULT result = v_aes_ecb_encrypt(h, data, len, out);
        if (result != SUCCESS) {
            free(h);
            return result;
        }
    } else if (operation_mode == CBC) {
        enum V_ENCRYPT_RESULT result = v_aes_cbc_encrypt(h, data, len, out);
        if (result != SUCCESS) {
            free(h);
            return result;
        }
    }
    free(h);
    return SUCCESS;
}

enum V_ENCRYPT_RESULT v_easy_decrypt(uint8_t* key, uint8_t* data, uint32_t len,
                                     uint16_t keyLen, uint8_t* out) {
    return v_aes_decrypt_implicit(key, data, len, keyLen, out, CTR);
}
enum V_ENCRYPT_RESULT v_aes_decrypt_implicit(
    uint8_t* key, uint8_t* data, uint32_t len, uint16_t keyLen, uint8_t* out,
    enum V_AES_OPERATE_MODE operation_mode) {
    // check if out pointer was allocated by user
    if (out == 0) {
        return OUT_NULL_POINTER;
    }
    if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
        return WRONG_SIZE_KEY;
    }
    if (key == 0) {
        return KEY_NULL;
    }
    if (data == 0) {
        return DATA_NULL;
    }

    v_aes_handle* h = v_aes_setupHandle(key, keyLen);
    if (operation_mode == CTR) {
        enum V_ENCRYPT_RESULT result = v_aes_ctr_perform(h, data, len, out, 1);
        if (result != SUCCESS) {
            free(h);
            return result;
        }
    } else if (operation_mode == ECB) {
        enum V_ENCRYPT_RESULT result = v_aes_ecb_decrypt(h, data, len, out);
        if (result != SUCCESS) {
            free(h);
            return result;
        }
    }else if (operation_mode == CBC) {
        enum V_ENCRYPT_RESULT result = v_aes_cbc_decrypt(h, data, len, out);
        if (result != SUCCESS) {
            free(h);
            return result;
        }
    }
    free(h);
    return SUCCESS;
}