#ifndef V_AES_H
#define V_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef __linux__
#include <stdint.h>
#endif
#include "v_types.h"
#include "v_util.h"



// constants

enum V_AES_OPERATE_MODE { CTR, ECB, CBC, CFB, OFB };

uint8_t _v_aes_getRound_amount(uint16_t keyLen);

typedef struct v_aes_handle {
    uint32_t size;
    uint32_t** encryptionKeys;
    uint32_t** decryptionKeys;
    uint16_t rounds;
} v_aes_handle;

typedef struct v_aes_counter {
    uint8_t* value;
} v_aes_counter;

v_aes_handle* v_aes_setupHandle(uint8_t* key, uint16_t keyLen);
void v_aes_freeHandle(v_aes_handle* handle);
v_aes_counter* v_aes_setupCounter(uint32_t initialValue);
void v_aes_setCounterBytes(v_aes_counter* handle, uint8_t* value);
void v_aes_counter_increment(v_aes_counter* handle);
void v_aes_base_encrypt(v_aes_handle* handle, uint8_t* data, uint32_t dataLen,
                        uint8_t* result);
void v_aes_base_decrypt(v_aes_handle* handle, uint8_t* data, uint32_t dataLen,
                        uint8_t* result);

enum V_ENCRYPT_RESULT v_aes_ctr_perform(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result,
                                        uint32_t counterValue);

enum V_ENCRYPT_RESULT v_aes_ecb_encrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result);
enum V_ENCRYPT_RESULT v_aes_ecb_decrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result);

enum V_ENCRYPT_RESULT v_aes_cbc_encrypt_iv(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result, uint8_t* iv);
enum V_ENCRYPT_RESULT v_aes_cbc_decrypt_iv(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result, uint8_t* iv);

enum V_ENCRYPT_RESULT v_aes_cbc_encrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result);
enum V_ENCRYPT_RESULT v_aes_cbc_decrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result);

enum V_ENCRYPT_RESULT v_aes_cfb_encrypt_iv(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result, uint8_t* iv, uint32_t segmentSize);
enum V_ENCRYPT_RESULT v_aes_cfb_decrypt_iv(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result, uint8_t* iv, uint32_t segmentSize);
enum V_ENCRYPT_RESULT v_aes_cfb_encrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result);
enum V_ENCRYPT_RESULT v_aes_cfb_decrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result);


enum V_ENCRYPT_RESULT v_aes_ofb_perform_iv(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result, uint8_t* iv);

enum V_ENCRYPT_RESULT v_aes_ofb_perform(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result);

#ifdef __cplusplus
}
#endif

#endif
