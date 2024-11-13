/*
 * MIT License
 *
 * Copyright (c) 2020-2024 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _CRYPT_H_
#define _CRYPT_H_

#include <stddef.h>

#define AES256_BLOCK_SIZE 16
#define AES256_KEY_SIZE   32
#define AES256_IV_SIZE    16

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_IV_SIZE  12

enum CRYPT_ALGO
{
    ALGO_NONE,
    ALGO_AES256_CBC,
    ALGO_CHACHA20,
};

enum CRYPT_MODE
{
    CRYPT_DECRYPT,
    CRYPT_ENCRYPT
};

enum CRYPT_STAT
{
    STAT_NOT_SECURE,
    STAT_SECURE
};

typedef struct
{
    unsigned char *iv;
    unsigned char *key;

    /* These methods are used to store next key and IV
     * so if secure negotiation is re-established
     * we won't lose session */

    unsigned char *next_iv;
    unsigned char *next_key;

    enum CRYPT_ALGO algo;
    enum CRYPT_ALGO next_algo;
    enum CRYPT_STAT secure;
} crypt_t;

crypt_t *crypt_create(void);

ssize_t crypt_generate_key(enum CRYPT_ALGO algo, unsigned char **key, unsigned char **iv);

size_t crypt_pkcs_decrypt(unsigned char *data, size_t length, unsigned char *pkey,
                          size_t pkey_length, unsigned char *result);
size_t crypt_pkcs_encrypt(unsigned char *data, size_t length, unsigned char *pkey,
                          size_t pkey_length, unsigned char *result);

ssize_t crypt_chacha20_encrypt(crypt_t *crypt, unsigned char *data,
                               size_t length, unsigned char **result);
ssize_t crypt_chacha20_decrypt(crypt_t *crypt, unsigned char *data,
                               size_t length, unsigned char **result);

ssize_t crypt_aes_encrypt(crypt_t *crypt, unsigned char *data,
                          size_t length, unsigned char **result);
ssize_t crypt_aes_decrypt(crypt_t *crypt, unsigned char *data,
                          size_t length, unsigned char **result);

ssize_t crypt_process(crypt_t *crypt, unsigned char *data, size_t length,
                      unsigned char **result, enum CRYPT_MODE mode);

void crypt_set_key(crypt_t *crypt, unsigned char *key, unsigned char *iv);
void crypt_set_secure(crypt_t *crypt, enum CRYPT_STAT secure);
void crypt_set_algo(crypt_t *crypt, enum CRYPT_ALGO algo);

void crypt_free(crypt_t *crypt);

#endif