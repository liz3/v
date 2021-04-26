#ifndef V_V_H
#define V_V_H

#ifdef __cplusplus 
extern "C" {
#endif

#include <stdint.h>
#include "aes.h"
#include "v_types.h"

/*
Easiest way to do encrypt data, this will implicitly do everything and replace
the data in place.
*/

char* v_easy_encrypt_c(char* key, char* data);
char* v_easy_decrypt_c(char* key, char* data);
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

#ifdef __cplusplus
}
#endif

#endif

