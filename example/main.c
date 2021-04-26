#include <stdio.h>
#include <stdlib.h>

#include "../src/v.h"
#include "../src/v_util.h"
#include <string.h>

int main() {
    const char* data = "This is pretty c";
    const uint8_t key[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                           11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                           22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    uint8_t* out = malloc(sizeof(uint8_t) * strlen(data) + 1);
    uint8_t* out2 = malloc(sizeof(uint8_t) * strlen(data) + 1);
    out[16] = '\0';
    out2[16] = '\0';
    enum V_ENCRYPT_RESULT res =
        v_aes_encrypt_implicit(key, data, strlen(data), 32, out, CBC);
    res = v_aes_decrypt_implicit(key, out, strlen(data), 32, out2, CBC);
 //   char * encrypted = v_easy_encrypt_c("SupersecretKey", data);
 //   char * decrypted = v_easy_decrypt_c("SupersecretKey", encrypted);
    printf("%s\n%s\n", out, out2);
    return 0;
}