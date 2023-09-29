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
#include <unistd.h>
#include <stdint.h>

#include <machine.h>

static uint64_t xor_shift_128_plus(uint64_t *seed)
{
    uint64_t seed1;
    uint64_t seed0;

    seed1 = seed[0];
    seed0 = seed[1];

    seed[0] = seed0;
    seed1 ^= seed1 << 23;
    seed[1] = seed[1] ^ seed[0] ^ (seed1 >> 18) ^ (seed0 >> 5);

    return seed[1] + seed0;
}

int machine_uuid(char *buffer)
{
    char *uuid;

    seed_t seed;
    uint64_t new_seed[2];

    int bytes_read;
    int iter;
    int part;

    #if defined(LINUX) || defined(MACOS)
    FILE *fp;

    fp = fopen("/dev/urandom", "rb");

    if (!fp)
        return -1;

    bytes_read = fread(new_seed, 1, sizeof(new_seed), fp);
    fclose(fp);

    if (bytes_read != sizeof(new_seed))
        return -1;

    #elif defined(WINDOWS)
    HCRYPTPROV hCryptProv;

    bytes_read = CryptAcquireContext(
        &hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

    if (!bytes_read)
        return -1;

    bytes_read = CryptGenRandom(hCryptProv, (DWORD) sizeof(seed), (PBYTE) new_seed);
    CryptReleaseContext(hCryptProv, 0);

    if (!bytes_read)
        return -1;

    #else
        return -1;
    #endif

    seed.word[0] = xor_shift_128_plus(new_seed);
    seed.word[1] = xor_shift_128_plus(new_seed);

    uuid = UUID;
    iter = 0;

    while (*uuid)
    {
        part = seed.b[iter >> 1];
        part = (iter & 1) ? (part >> 4) : (part & 0xf);

        switch (*uuid)
        {
            case 'x':
                *buffer = UUID_CHARS[j];
                iter++;
                break;
            case 'y':
                *buffer = UUID_CHARS[(j & 0x3) + 8];
                iter++;
                break;
            default:
                *buffer = *uuid;
        }

        buffer++;
        uuid++;
    }

    *buffer = '\0';
    return 0;
}
