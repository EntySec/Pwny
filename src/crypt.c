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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <mbedtls/aes.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>

#include <log.h>
#include <crypt.h>

static ssize_t crypt_apply_padding(unsigned char *data, size_t length,
                                   unsigned char **result)
{
    size_t pad_size;
    size_t pad_length;

    pad_size = length + (AES256_BLOCK_SIZE - (length % AES256_BLOCK_SIZE));

    *result = malloc(pad_size);
    if (*result == NULL)
    {
        log_debug("* Failed to add padding to data\n");
        return -1;
    }

    memcpy(*result, data, length);
    pad_length = pad_size - length;
    memset(*result + length, pad_length, pad_length);

    return pad_size;
}

crypt_t *crypt_create(void)
{
    int status;
    crypt_t *crypt;

    crypt = calloc(1, sizeof(*crypt));

    if (crypt == NULL)
    {
        return NULL;
    }

    crypt->secure = STAT_NOT_SECURE;
    crypt->algo = ALGO_NONE;
    crypt->key = NULL;
    crypt->iv = NULL;

    mbedtls_entropy_init(&crypt->entropy);
    mbedtls_ctr_drbg_init(&crypt->ctr_drbg);

    status = mbedtls_ctr_drbg_seed(&crypt->ctr_drbg, mbedtls_entropy_func,
                                   &crypt->entropy, NULL, 0);
    if (status != 0)
    {
        log_debug("* Failed to seed PRNG (%d)\n", status);
        free(crypt);

        mbedtls_entropy_free(&crypt->entropy);
        mbedtls_ctr_drbg_free(&crypt->ctr_drbg);

        return NULL;
    }

    return crypt;
}

ssize_t crypt_generate_key(crypt_t *crypt, enum CRYPT_ALGO algo,
                           unsigned char **key, unsigned char **iv)
{
    ssize_t length;
    int status;

    size_t key_size;
    size_t iv_size;

    status = 0;

    switch (algo)
    {
        case ALGO_CHACHA20:
            log_debug("* Generating key for ALGO_CHACHA20 (%d)\n",
                      ALGO_CHACHA20);
            key_size = CHACHA20_KEY_SIZE;
            iv_size = CHACHA20_IV_SIZE;

            break;
        case ALGO_AES256_CBC:
            log_debug("* Generating key for ALGO_AES256_CBC (%d)\n",
                      ALGO_AES256_CBC);
            key_size = AES256_KEY_SIZE;
            iv_size = AES256_IV_SIZE;

            break;
        case ALGO_NONE:
            log_debug("* No ALGO selected, skipping init\n");
            return -1;
        default:
            return -1;
    }

    *iv = calloc(iv_size, 1);

    if (*iv == NULL)
    {
        log_debug("* Failed to allocate memory for IV\n");
        return key_size;
    }

    *key = calloc(key_size, 1);

    if (*key == NULL)
    {
        log_debug("* Failed to allocate memory for key\n");
        free(*iv);

        return key_size;
    }

    status = mbedtls_ctr_drbg_random(&crypt->ctr_drbg, *key, key_size);
    if (status != 0)
    {
        log_debug("* Failed to generate key (%d)\n", status);
        goto fail;
    }

    status = mbedtls_ctr_drbg_random(&crypt->ctr_drbg, *iv, iv_size);
    if (status != 0)
    {
        log_debug("* Failed to generate IV (%d)\n", status);
        goto fail;
    }

    return key_size;

fail:
    free(*iv);
    free(*key);

    return key_size;
}

void crypt_set_key(crypt_t *crypt, unsigned char *key, unsigned char *iv)
{
    size_t key_size;
    size_t iv_size;

    switch (crypt->algo)
    {
        case ALGO_CHACHA20:
            key_size = CHACHA20_KEY_SIZE;
            iv_size = CHACHA20_IV_SIZE;

            break;
        case ALGO_AES256_CBC:
            key_size = AES256_KEY_SIZE;
            iv_size = AES256_IV_SIZE;

            break;
        case ALGO_NONE:
            return;
        default:
            return;
    }

    if (!crypt->key)
    {
        crypt->key = calloc(key_size, 1);
    }

    if (!crypt->iv)
    {
        crypt->iv = calloc(iv_size, 1);
    }

    memcpy(crypt->iv, iv, iv_size);
    memcpy(crypt->key, key, key_size);
}

size_t crypt_pkcs_decrypt(crypt_t *crypt, unsigned char *data, size_t length, unsigned char *pkey,
                          size_t pkey_length, unsigned char *result)
{
    int status;
    mbedtls_pk_context pk;

    size_t result_size;
    result_size = 0;

    mbedtls_pk_init(&pk);
    status = mbedtls_pk_parse_key(&pk, pkey, pkey_length, NULL, 0);

    if (status != 0)
    {
        log_debug("* Failed to parse private key (%d)\n", status);
        goto finalize;
    }

    status = mbedtls_pk_decrypt(&pk, data, length, result, &result_size,
                                sizeof(result), mbedtls_ctr_drbg_random,
                                &crypt->ctr_drbg);
    if (status != 0)
    {
        log_debug("* Failed to decrypt key with PKCS (%d)\n", status);
        goto finalize;
    }

finalize:
    mbedtls_pk_free(&pk);
    return result_size;
}

size_t crypt_pkcs_encrypt(crypt_t *crypt, unsigned char *data, size_t length, unsigned char *pkey,
                          size_t pkey_length, unsigned char *result)
{
    int status;
    unsigned char buffer[MBEDTLS_MPI_MAX_SIZE];

    mbedtls_pk_context pk;

    size_t result_size;
    result_size = 0;

    mbedtls_pk_init(&pk);
    status = mbedtls_pk_parse_public_key(&pk, pkey, pkey_length);

    if (status != 0)
    {
        log_debug("* Failed to parse public key (%d)\n", status);
        goto finalize;
    }

    memset(buffer, '\0', MBEDTLS_MPI_MAX_SIZE);
    status = mbedtls_pk_encrypt(&pk, data, length, buffer, &result_size,
                                sizeof(buffer), mbedtls_ctr_drbg_random,
                                &crypt->ctr_drbg);
    if (status != 0)
    {
        log_debug("* Failed to encrypt key with PKCS (%d)\n", status);
        goto finalize;
    }

    memcpy(result, buffer, result_size);

finalize:
    mbedtls_pk_free(&pk);
    return result_size;
}

ssize_t crypt_chacha20_encrypt(crypt_t *crypt, unsigned char *data,
                               size_t length, unsigned char **result)
{
    int status;
    unsigned char iv[CHACHA20_IV_SIZE];

    mbedtls_chacha20_context chacha20;

    mbedtls_chacha20_init(&chacha20);
    mbedtls_chacha20_setkey(&chacha20, crypt->key);

    status = mbedtls_ctr_drbg_random(&crypt->ctr_drbg, iv, CHACHA20_IV_SIZE);

    if (status != 0)
    {
        log_debug("* Failed to generate IV (%d)\n", status);
        goto fail;
    }

    crypt_set_key(crypt, crypt->key, iv);
    status = mbedtls_chacha20_starts(&chacha20, crypt->iv, 0);

    if (status != 0)
    {
        log_debug("* Failed to initialize crypt context (%d)\n", status);
        goto fail;
    }

    *result = calloc(CHACHA20_IV_SIZE + length, 1);
    if (*result == NULL)
    {
        log_debug("* Failed to allocate memory for result\n");
        goto fail;
    }

    mbedtls_chacha20_update(&chacha20, length, data, *result + CHACHA20_IV_SIZE);
    memcpy(*result, crypt->iv, CHACHA20_IV_SIZE);

    length += CHACHA20_IV_SIZE;

    mbedtls_chacha20_free(&chacha20);

    log_debug("* IV:\n");
    log_hexdump(crypt->iv, AES256_IV_SIZE);

    return length;

fail:
    mbedtls_chacha20_free(&chacha20);
    return -1;
}

ssize_t crypt_aes_encrypt(crypt_t *crypt, unsigned char *data,
                          size_t length, unsigned char **result)
{
    int status;
    mbedtls_aes_context aes;

    unsigned char *padded;
    unsigned char *encrypted;

    unsigned char iv[AES256_IV_SIZE];

    memcpy(iv, crypt->iv, AES256_IV_SIZE);

    if (length % 16 != 0)
    {
        length = crypt_apply_padding(data, length, &padded);
    }
    else
    {
        padded = malloc(length);
        if (padded == NULL)
        {
            return -1;
        }
        memcpy(padded, data, length);
    }

    if (length <= 0)
    {
        log_debug("* Length is too small to encrypt (%d)\n", length);
        free(padded);
        return -1;
    }

    *result = calloc(AES256_IV_SIZE + length, 1);
    if (*result == NULL)
    {
        log_debug("* Failed to allocate memory for result\n");
        free(padded);
        return -1;
    }

    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, crypt->key, 256);

    status = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length,
                                   crypt->iv, padded, *result + AES256_IV_SIZE);
    mbedtls_aes_free(&aes);
    free(padded);

    if (status != 0)
    {
        log_debug("* Failed to encrypt with ALGO_AES256_CBC (%d)\n",
                  status);
        free(*result);
        return -1;
    }

    log_debug("* IV:\n");
    log_hexdump(iv, AES256_IV_SIZE);

    memcpy(*result, iv, AES256_IV_SIZE);
    length += AES256_IV_SIZE;

    return length;
}

ssize_t crypt_chacha20_decrypt(crypt_t *crypt, unsigned char *data,
                               size_t length, unsigned char **result)
{
    int status;
    unsigned char iv[CHACHA20_IV_SIZE];

    mbedtls_chacha20_context chacha20;
    length -= CHACHA20_IV_SIZE;
    memcpy(iv, data, CHACHA20_IV_SIZE);

    *result = malloc(length);

    if (*result == NULL)
    {
        log_debug("* Failed to allocate space for result\n");
        return -1;
    }

    mbedtls_chacha20_init(&chacha20);
    mbedtls_chacha20_setkey(&chacha20, crypt->key);

    status = mbedtls_chacha20_starts(&chacha20, iv, 0);

    if (status != 0)
    {
        log_debug("* Failed to initialize crypto context (%d)\n", status);
        mbedtls_chacha20_free(&chacha20);
        return -1;
    }

    mbedtls_chacha20_update(&chacha20, length, data + CHACHA20_IV_SIZE, *result);
    mbedtls_chacha20_free(&chacha20);

    return length;
}

ssize_t crypt_aes_decrypt(crypt_t *crypt, unsigned char *data,
                          size_t length, unsigned char **result)
{
    int status;
    unsigned char iv[AES256_IV_SIZE];

    mbedtls_aes_context aes;

    length -= AES256_IV_SIZE;
    *result = malloc(length);

    if (*result == NULL)
    {
        log_debug("* Failed to allocate space for result\n");
        return -1;
    }

    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, crypt->key, 256);

    memcpy(iv, data, AES256_IV_SIZE);

    status = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length,
                                   iv, data + AES256_IV_SIZE, *result);
    mbedtls_aes_free(&aes);

    if (status != 0)
    {
        log_debug("* Failed to decrypt with ALGO_AES256_CBC (%d)\n",
                  status);
        free(*result);
        return -1;
    }

    return length;
}

ssize_t crypt_process(crypt_t *crypt, unsigned char *data, size_t length,
                      unsigned char **result, enum CRYPT_MODE mode)
{
    ssize_t result_length;

    if (crypt == NULL || !crypt->secure)
    {
        *result = malloc(length);
        memcpy(*result, data, length);
        return length;
    }

    result_length = -1;

    switch (crypt->algo)
    {
        case ALGO_CHACHA20:
            log_debug("* Processing data with ALGO_CHACHA20 (%d)\n",
                      ALGO_CHACHA20);
            switch (mode)
            {
                case CRYPT_DECRYPT:
                    result_length = crypt_chacha20_decrypt(crypt, data, length, result);
                    break;
                case CRYPT_ENCRYPT:
                    result_length = crypt_chacha20_encrypt(crypt, data, length, result);
                    break;
                default:
                    break;
            }
            break;
        case ALGO_AES256_CBC:
            log_debug("* Processing data with ALGO_AES256_CBC (%d)\n",
                      ALGO_AES256_CBC);
            switch (mode)
            {
                case CRYPT_DECRYPT:
                    result_length = crypt_aes_decrypt(crypt, data, length, result);
                    break;
                case CRYPT_ENCRYPT:
                    result_length = crypt_aes_encrypt(crypt, data, length, result);
                    break;
                default:
                    break;
            }
            break;
        case ALGO_NONE:
            log_debug("* No ALGO selected, skipping processing\n");
            break;
        default:
            break;
    }

    return result_length;
}

void crypt_set_secure(crypt_t *crypt, enum CRYPT_STAT secure)
{
    log_debug("* Security is set to (%d), refer to CRYPT_STAT\n", secure);
    crypt->secure = secure;
}

void crypt_set_algo(crypt_t *crypt, enum CRYPT_ALGO algo)
{
    log_debug("* ALGO is set to (%d), refer to CRYPT_ALGO\n", algo);
    crypt->algo = algo;
}

void crypt_free(crypt_t *crypt)
{
    if (crypt->key)
    {
        free(crypt->key);
    }

    if (crypt->iv)
    {
        free(crypt->iv);
    }

    mbedtls_entropy_free(&crypt->entropy);
    mbedtls_ctr_drbg_free(&crypt->ctr_drbg);

    free(crypt);
}
