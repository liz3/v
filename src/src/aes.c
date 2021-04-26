#include "aes.h"

#include "aes_constants.h"

uint8_t _v_aes_getRound_amount(uint16_t keyLen) {
    switch (keyLen) {
        case 16:
            return 10;
        case 24:
            return 12;
        case 32:
            return 14;
    }
    return 0;
}
v_aes_handle* v_aes_setupHandle(uint8_t* key, uint16_t keyLen) {
    v_aes_handle* handle = malloc(sizeof(v_aes_handle));

    uint8_t roundsRquired = _v_aes_getRound_amount(keyLen);
    if (roundsRquired == 0) {
        goto error_baleout;
    }

    uint32_t* encryptionKeys = malloc(sizeof(uint32_t) * ((roundsRquired + 1) * 4));
    uint32_t* decryptionKeys = malloc(sizeof(uint32_t) * ((roundsRquired + 1) * 4));

    for (size_t i = 0; i <= roundsRquired; i++) {
        *(encryptionKeys + (i * 4)) = 0;
        *(encryptionKeys + (i * 4) + 1) = 0;
        *(encryptionKeys + (i * 4) + 2) = 0;
        *(encryptionKeys + (i * 4) + 3) = 0;

        *(decryptionKeys + (i * 4)) = 0;
        *(decryptionKeys + (i * 4) + 1) = 0;
        *(decryptionKeys + (i * 4) + 2) = 0;
        *(decryptionKeys + (i * 4) + 3) = 0;
    }
    uint32_t roundKeyCount = (roundsRquired + 1) * 4;
    uint32_t kc = keyLen / 4;
    uint32_t* keyInts = malloc(sizeof(uint32_t) * kc);
    v_dataToIntArray(key, keyInts, kc);
    
    uint32_t index;
    for (int32_t i = 0; i < kc; i++) {
        index = i >> 2;
        encryptionKeys[index * 4 + (i % 4)] = keyInts[i];
        decryptionKeys[((roundsRquired - index) * 4) + (i % 4)] = keyInts[i];
    }

    uint32_t rconpointer = 0;
    uint32_t t = kc;
    uint32_t tt = 0;
    while (t < roundKeyCount) {
        tt = keyInts[kc - 1];
        keyInts[0] ^= ((V_S[(tt >> 16) & 0xFF] << 24) ^
                       (V_S[(tt >> 8) & 0xFF] << 16) ^ (V_S[tt & 0xFF] << 8) ^
                       V_S[(tt >> 24) & 0xFF] ^ (V_RCON[rconpointer] << 24));
        rconpointer++;

        if (kc != 8) {
            for (uint32_t i = 1; i < kc; i++) {
                keyInts[i] ^= keyInts[i - 1];
            }
        } else {
            for (uint32_t i = 1; i < kc / 2; i++) {
                keyInts[i] ^= keyInts[i - 1];
            }
            tt = keyInts[(kc / 2) - 1];
            keyInts[kc / 2] ^= (V_S[tt & 0xFF] ^ (V_S[(tt >> 8) & 0xFF] << 8) ^
                                (V_S[(tt >> 16) & 0xFF] << 16) ^
                                (V_S[(tt >> 24) & 0xFF] << 24));

            for (uint32_t i = (kc / 2) + 1; i < kc; i++) {
                keyInts[i] ^= keyInts[i - 1];
            }
        }
        uint32_t i = 0;
        uint32_t r, c;
        printf("%d\n", t);
        while (i < kc && t < roundKeyCount) {
            r = t >> 2;
            c = t % 4;
            encryptionKeys[(r * 4) + c] = keyInts[i];
            decryptionKeys[((roundsRquired - r) * 4) + c] = keyInts[i++];
            t++;
        }
    }

    for (uint32_t i = 1; i < roundsRquired; i++) {
        for (uint32_t c = 0; c < 4; c++) {
            tt = decryptionKeys[(i * 4) + c];
            decryptionKeys[(i * 4) + c] =
                (V_U1[(tt >> 24) & 0xFF] ^ V_U2[(tt >> 16) & 0xFF] ^
                 V_U3[(tt >> 8) & 0xFF] ^ V_U4[tt & 0xFF]);
        }
    }
    handle->decryptionKeys = decryptionKeys;
    handle->encryptionKeys = encryptionKeys;
    handle->size = roundsRquired * 4;
    handle->rounds = roundsRquired;
    goto success_ret;

error_baleout:
    free(handle);
    handle = 0;
    return 0;
success_ret:
    free(keyInts);
    keyInts = 0;
    return handle;
}

void v_aes_base_encrypt(v_aes_handle* handle, uint8_t* data, uint32_t dataLen,
                        uint8_t* result) {
    if (dataLen != 16) {
        return;
    }
    if (handle == 0) {
        return;
    }
    if (data == 0) {
        return;
    }
    uint32_t rounds = handle->rounds;
    uint32_t* a = malloc(sizeof(uint32_t) * 4);
    for (size_t i = 0; i < 4; i++) {
        *(a + i) = 0;
    }
    uint32_t* t = malloc(sizeof(uint32_t) * 4);
    v_dataToIntArray(data, t, 4);
    for (size_t i = 0; i < 4; i++) {
        t[i] ^= handle->encryptionKeys[i];
    }
    for (size_t r = 1; r < rounds; r++) {
        for (size_t i = 0; i < 4; i++) {
            a[i] = (V_T1[(t[i] >> 24) & 0xff] ^
                    V_T2[(t[(i + 1) % 4] >> 16) & 0xff] ^
                    V_T3[(t[(i + 2) % 4] >> 8) & 0xff] ^
                    V_T4[t[(i + 3) % 4] & 0xff] ^
                    handle->encryptionKeys[(r * 4) + i]);
        }
        for (size_t i = 0; i < 4; i++) {
            t[i] = a[i];
        }
    }
    uint8_t* resultP = result;

    uint32_t tt;
    for (size_t i = 0; i < 4; i++) {
        tt = handle->encryptionKeys[(rounds * 4) + i];
        result[4 * i] = (V_S[(t[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff;
        result[(4 * i) + 1] =
            (V_S[(t[(i + 1) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff;
        result[(4 * i) + 2] =
            (V_S[(t[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff;
        result[(4 * i) + 3] = (V_S[t[(i + 3) % 4] & 0xff] ^ tt) & 0xff;
    }

    free(a);
    free(t);
    a = 0;
    t = 0;
}

void v_aes_base_decrypt(v_aes_handle* handle, uint8_t* data, uint32_t dataLen,
                        uint8_t* result) {
    if (dataLen != 16) {
        return;
    }
    printf("test\n");
    uint32_t rounds = handle->rounds;
    uint32_t* a = malloc(sizeof(uint32_t) * 4);
    for (size_t i = 0; i < 4; i++) {
        *(a + i) = 0;
    }
    uint32_t* t = malloc(sizeof(uint32_t) * 4);
    v_dataToIntArray(data, t, 4);
    for (size_t i = 0; i < 4; i++) {
        t[i] ^= handle->decryptionKeys[i];
    }

    for (size_t r = 1; r < rounds; r++) {
        for (size_t i = 0; i < 4; i++) {
            a[i] = (V_T5[(t[i] >> 24) & 0xff] ^
                    V_T6[(t[(i + 3) % 4] >> 16) & 0xff] ^
                    V_T7[(t[(i + 2) % 4] >> 8) & 0xff] ^
                    V_T8[t[(i + 1) % 4] & 0xff] ^
                    handle->decryptionKeys[(r * 4) + i]);
        }
        for (size_t i = 0; i < 4; i++) {
            t[i] = a[i];
        }
    }

    uint8_t* resultP = result;
    uint32_t tt;
    for (size_t i = 0; i < 4; i++) {
        printf("dd: %d\n", (rounds * 4) + i);
        tt = handle->decryptionKeys[(rounds * 4) + i];
        result[4 * i] = (V_Si[(t[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff;
        result[(4 * i) + 1] =
            (V_Si[(t[(i + 3) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff;
        result[(4 * i) + 2] =
            (V_Si[(t[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff;
        result[(4 * i) + 3] = (V_Si[t[(i + 1) % 4] & 0xff] ^ tt) & 0xff;
    }
    free(a);
    free(t);
    a = 0;
    t = 0;
}

// counter logic
v_aes_counter* v_aes_setupCounter(uint32_t initialValue) {
    v_aes_counter* counter = malloc(sizeof(v_aes_counter));
    counter->value = malloc(sizeof(uint8_t) * 16);
    uint32_t v = initialValue;
    for (int8_t i = 15; i >= 0; i--) {
        counter->value[i] = v % 256;
        v = v / 256;
    }
    return counter;
}
void v_aes_counter_increment(v_aes_counter* handle) {
    for (int8_t i = 15; i >= 0; i--) {
        if (handle->value[i] == 255) {
            handle->value[i] = 0;
        } else {
            handle->value[i]++;
        }
    }
}
void v_aes_setCounterBytes(v_aes_counter* handle, uint8_t* value) {
    for (size_t i = 0; i < 15; i++) {
        handle->value[i] = value[i];
    }
}

// encryption modes
enum V_ENCRYPT_RESULT v_aes_ctr_perform(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result,
                                        uint32_t counterValue) {
    v_aes_counter* counter = v_aes_setupCounter(counterValue);
    uint8_t remainingCounterIndex = 16;
    uint8_t* remainingCounter = malloc(sizeof(uint8_t) * 16);
    uint8_t* resultP = result;
    for (size_t i = 0; i < dataLen; i++) {
        resultP[i] = data[i];
    }
    for (size_t i = 0; i < dataLen; i++) {
        if (remainingCounterIndex == 16) {
            v_aes_base_encrypt(handle, counter->value, 16, remainingCounter);
            remainingCounterIndex = 0;
            v_aes_counter_increment(counter);
        }
        resultP[i] ^= remainingCounter[remainingCounterIndex++];
    }
    free(counter->value);
    free(counter);
    free(remainingCounter);
    return SUCCESS;
}

enum V_ENCRYPT_RESULT v_aes_ecb_encrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result) {
    if (dataLen % 16 != 0) {
        return ECB_ALIGMENT_ISSUE;
    }
    uint8_t* block = malloc(sizeof(uint8_t) * 16);
    uint8_t* block2 = malloc(sizeof(uint8_t) * 16);
    for (size_t i = 0; i < dataLen; i += 16) {
        v_copy(data, block, 0, i, 16);
        v_aes_base_encrypt(handle, block, 16, block2);
        v_copy(block2, result, i, 0, 16);
    }
    free(block);
    free(block2);
    return SUCCESS;
}
enum V_ENCRYPT_RESULT v_aes_ecb_decrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result) {
    if (dataLen % 16 != 0) {
        return ECB_ALIGMENT_ISSUE;
    }
    uint8_t* block = malloc(sizeof(uint8_t) * 16);
    uint8_t* block2 = malloc(sizeof(uint8_t) * 16);

    for (size_t i = 0; i < dataLen; i += 16) {
        v_copy(data, block, 0, i, 16);
        v_aes_base_decrypt(handle, block, 16, block2);
        v_copy(block2, result, i, 0, 16);
    }
    free(block);
    free(block2);
    return SUCCESS;
}

enum V_ENCRYPT_RESULT v_aes_cbc_encrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result) {
    uint8_t* lastCipherBlock = malloc(sizeof(uint8_t) * 16);

    uint8_t* block = malloc(sizeof(uint8_t) * 16);

    for (size_t i = 0; i < dataLen; i += 16) {
        v_copy(data, block, 0, i, 16);
        for (size_t j = 0; j < 16; j++) {
            block[j] ^= lastCipherBlock[j];
        }
        v_aes_base_encrypt(handle, block, 16, lastCipherBlock);
        v_copy(lastCipherBlock, result, i, 0, 16);
    }
    free(block);
    free(lastCipherBlock);
    return SUCCESS;
}
enum V_ENCRYPT_RESULT v_aes_cbc_decrypt(v_aes_handle* handle, uint8_t* data,
                                        uint32_t dataLen, uint8_t* result) {
    uint8_t* lastCipherBlock = malloc(sizeof(uint8_t) * 16);

    uint8_t* block = malloc(sizeof(uint8_t) * 16);
    uint8_t* block2 = malloc(sizeof(uint8_t) * 16);

    for (size_t i = 0; i < dataLen; i += 16) {
        v_copy(data, block, 0, i, 16);
        v_aes_base_decrypt(handle, block, 16, block2);

        for (size_t j = 0; j < 16; j++) {
            result[i + j] = block2[j] ^= lastCipherBlock[j];
        }
        v_copy(data, lastCipherBlock, 0, i, 16);
    }
    free(block);
    free(lastCipherBlock);
    free(block2);
    return SUCCESS;
}