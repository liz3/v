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
    enum V_ENCRYPT_RESULT result;
    if (operation_mode == CTR) {
      result = v_aes_ctr_perform(h, data, len, out, 1);
    } else if (operation_mode == ECB) {
      result = v_aes_ecb_encrypt(h, data, len, out);
    } else if (operation_mode == CBC) {
      result = v_aes_cbc_encrypt(h, data, len, out);
    } else if (operation_mode == CFB) {
      result = v_aes_cfb_encrypt(h, data, len, out);
    } else if (operation_mode == OFB) {
      result = v_aes_ofb_perform(h, data, len, out);
    } else {
      result = INVALID_MODE;
    }
    v_aes_freeHandle(h);
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
    if(h == 0) {
      return INVALID_HANDLE;
    }
    enum V_ENCRYPT_RESULT result;
    if (operation_mode == CTR) {
        result = v_aes_ctr_perform(h, data, len, out, 1);
    } else if (operation_mode == ECB) {
        result = v_aes_ecb_decrypt(h, data, len, out);
    } else if (operation_mode == CBC) {
        result = v_aes_cbc_decrypt(h, data, len, out);
    } else if (operation_mode == CFB) {
        result = v_aes_cfb_decrypt(h, data, len, out);
    } else if (operation_mode == OFB) {
        result = v_aes_ofb_perform(h, data, len, out);
    } else {
      result = INVALID_MODE;
    }
    v_aes_freeHandle(h);
    free(h);
    return result;
}

char* v_easy_encrypt_c(char* key, char* data) {
    if(key == 0 || data == 0) {
        return 0;
    }
    size_t keyLen = v_strlen(key);
    size_t keySize = 0;
    uint8_t* keyP = 0;
    if (keyLen == 16 || keyLen == 24 || keyLen == 32) {
        keySize = keyLen;
        keyP = malloc(sizeof(uint8_t) * keySize);
        v_copy(key, keyP, 0, 0, keySize);
    } else if (keyLen < 32) {
        keySize = 32;
        keyP = malloc(sizeof(uint8_t) * keySize);
        v_copy(key, keyP, 0, 0, keyLen);
    }else {
        keySize = 32;
        keyP = malloc(sizeof(uint8_t) * keySize);
        v_copy(key, keyP, 0, 0, 32);
    }
    size_t dataSize = v_strlen(data);
    uint8_t* outBuffer = malloc(sizeof(uint8_t) * dataSize + 1);
    enum V_ENCRYPT_RESULT res =
        v_aes_encrypt_implicit(keyP, data, dataSize, keySize, outBuffer, CTR);
    free(keyP);
    keyP = 0;
    if (res != SUCCESS) {
        free(outBuffer);
        outBuffer = 0;
        return 0;
    }
    outBuffer[dataSize] = '\0';
    return outBuffer;
}
char* v_easy_decrypt_c(char* key, char* data) {
    return v_easy_encrypt_c(key, data);
}
