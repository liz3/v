#ifndef V_V_H
#define V_V_H

#include <stdint.h>

#include "aes.h"
#include "v_types.h"

/*
Easiest way to do encrypt data, this will implicitly do everything and replace
the data in place.
*/
enum V_ENCRYPT_RESULT v_easy_encrypt(uint8_t* key, uint8_t* data, uint32_t len,
                                     uint16_t keyLen, uint8_t* out);
enum V_ENCRYPT_RESULT v_aes_encrypt_implicit(
    uint8_t* key, uint8_t* data, uint32_t len, uint16_t keyLen, uint8_t* out,
    enum V_AES_OPERATE_MODE operation_mode);

enum V_ENCRYPT_RESULT v_easy_decrypt(uint8_t* key, uint8_t* data, uint32_t len,
                                     uint16_t keyLen, uint8_t* out);
enum V_ENCRYPT_RESULT v_aes_decrypt_implicit(
    uint8_t* key, uint8_t* data, uint32_t len, uint16_t keyLen, uint8_t* out,
    enum V_AES_OPERATE_MODE operation_mode);

#endif