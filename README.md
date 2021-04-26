# V
DO NOT USE THIS IN A CRITICAL ENVIRONMENT AT THIS POINT OF TIME I CANNOT GUARANTEE SAFTEY YET.

I will keep this updated should it be safe.

## v
v is a pure c implementation of the AES algorithm.  
The target is to keep the implementation as simple as possible while still offering a userfriendly api.

V has support for all common modes CTR, ECB, CBC, CFB and OFB.  

V should be useable on 32 bit and a lot of platforms, the only required systems to run are the types uint32, uint8.. and malloc/free.
no other library.

I would also like to write some bindings for languages once ive confirmed there are no way to leak data.

## Usage examples

### The easiest example is literally one line of code:
```c
#include <v.h>

int main() {
    char* enrypted = v_easy_encrypt_c("SupersecretKey", "some nice data to encrypt");
    return 0;
}
```
Note that in this example `v_easy_encrypt_c` will return 0/NULL if an error occured or a null terminated string with the encrypted data,
 a mirrored function called `v_easy_decrypt_c` is present.
### Normal usage with error processing

```c
#include <v.h>

int main() {
    const char* data = "This is pretty cool data";
    const uint8_t key[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                            22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    uint8_t* encryptedBuffer = malloc(sizeof(uint8_t)* strlen(data));
    enum V_ENCRYPT_RESULT res =                               
         v_aes_encrypt_implicit(key, data, strlen(data), 32, encryptedBuffer, CTR); // 32 is the key length, needs to be 16/24/32
    if(res != SUCCESS) {
        // error handling
        free(encryptedBuffer);
        return 1;
    }
    //....
    free(encryptedBuffer);
    return 0;
}
```
Here theres also a mirror function called `v_aes_decrypt_implicit` present.
### Control usage
This allowes the most control over the api.
```c
#include <v.h>

int main() {
    const uint8_t key[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                            22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    const char* data = "This is pretty cool data";
    uint8_t* encryptedBuffer = malloc(sizeof(uint8_t)* strlen(data));
    v_aes_handle* handle = v_aes_setupHandle(key, 32);
    enum V_ENCRYPT_RESULT result = v_aes_cbc_encrypt(h, data, strlen(data), encryptedBuffer);
     if (result != SUCCESS) {
        free(handle);
        return 1;
    }

    free(handle);
    return 0;
}

```

# Credits
This was inspired by the [Javascript implementation of ricmoo](https://github.com/ricmoo/aes-js)

# License
This is free software licensed under GPL-2