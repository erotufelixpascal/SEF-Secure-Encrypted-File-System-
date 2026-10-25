#include "chunk.h"
#include "crypto.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#define CONTENT_OFF (SEFS_NEXT_FIELD_LEN + SEFS_SIZE_FIELD_LEN)

static void put_u32(unsigned char *p, unsigned long v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static unsigned long get_u32(const unsigned char *p)
{
    return (unsigned long)p[0] << 24 | (unsigned long)p[1] << 16 | (unsigned long)p[2] << 8 | p[3];
}

int chunk_new_name(char *out)
{
    unsigned char r[SEFS_CHUNK_NAME_BYTES];
    char path[256];
    int tries;

    for (tries = 0; tries < 8; tries++) {
        if (gen_random(r, sizeof r) != SEFS_OK)
            return SEFS_ERR;
        to_hex(r, sizeof r, out);
        if (chunk_path(out, path, sizeof path) != SEFS_OK)
            return SEFS_ERR;
        if (!file_exists(path))
            return SEFS_OK;
    }
    return SEFS_ERR;
}

int chunk_write(const char *name, const char *next, const unsigned char *data, size_t size, chunk_ref *ref)
{
    unsigned char plain[SEFS_BODY_LEN], file[SEFS_CHUNK_FILE_LEN];
    char path[256];
    int ok;

    if (size > SEFS_CHUNK_SIZE || strlen(name) != SEFS_CHUNK_NAME_LEN)
        return SEFS_ERR;
    if (next != NULL && strlen(next) != SEFS_CHUNK_NAME_LEN)
        return SEFS_ERR;

    memset(plain, 0, SEFS_NEXT_FIELD_LEN);
    if (next == NULL)
        memcpy(plain, SEFS_NULL_NAME, strlen(SEFS_NULL_NAME));
    else
        memcpy(plain, next, SEFS_CHUNK_NAME_LEN);
    put_u32(plain + SEFS_NEXT_FIELD_LEN, (unsigned long)size);
    memset(plain + CONTENT_OFF, SEFS_PAD_BYTE, SEFS_CHUNK_SIZE);
    if (size > 0)
        memcpy(plain + CONTENT_OFF, data, size);

    memcpy(ref->name, name, SEFS_CHUNK_NAME_LEN + 1);
    /* Fresh key and IV on every write, so a CTR keystream is never reused. */
    ok = gen_random(ref->key, SEFS_KEY_LEN) == SEFS_OK &&
         gen_random(file, SEFS_IV_LEN) == SEFS_OK &&
         aes128_ctr(ref->key, file, plain, SEFS_BODY_LEN, file + SEFS_IV_LEN) == SEFS_OK &&
         hmac_sha256(ref->key, file, SEFS_CHUNK_FILE_LEN, ref->hmac) == SEFS_OK &&
         chunk_path(name, path, sizeof path) == SEFS_OK &&
         write_atomic(path, file, sizeof file) == SEFS_OK;
    OPENSSL_cleanse(plain, sizeof plain);
    return ok ? SEFS_OK : SEFS_ERR;
}

int chunk_read(const chunk_ref *ref, unsigned char *content, size_t *size, char *next)
{
    unsigned char *file = NULL, plain[SEFS_BODY_LEN], mac[SEFS_HMAC_LEN];
    size_t len, i, sz, nulllen = strlen(SEFS_NULL_NAME);
    char path[256];
    int ok = 0;

    if (chunk_path(ref->name, path, sizeof path) != SEFS_OK || read_all(path, &file, &len) != SEFS_OK)
        return SEFS_ERR;
    if (len != SEFS_CHUNK_FILE_LEN)
        goto done;
    /* Integrity before decryption */
    if (hmac_sha256(ref->key, file, len, mac) != SEFS_OK ||
        CRYPTO_memcmp(mac, ref->hmac, SEFS_HMAC_LEN) != 0)
        goto done;
    if (aes128_ctr(ref->key, file, file + SEFS_IV_LEN, SEFS_BODY_LEN, plain) != SEFS_OK)
        goto done;

    if (memcmp(plain, SEFS_NULL_NAME, nulllen) == 0) {
        for (i = nulllen; i < SEFS_NEXT_FIELD_LEN; i++)
            if (plain[i] != 0)
                goto done;
        next[0] = '\0';
    } else {
        if (!is_hex_string((const char *)plain, SEFS_CHUNK_NAME_LEN))
            goto done;
        for (i = SEFS_CHUNK_NAME_LEN; i < SEFS_NEXT_FIELD_LEN; i++)
            if (plain[i] != 0)
                goto done;
        memcpy(next, plain, SEFS_CHUNK_NAME_LEN);
        next[SEFS_CHUNK_NAME_LEN] = '\0';
    }

    sz = get_u32(plain + SEFS_NEXT_FIELD_LEN);
    if (sz > SEFS_CHUNK_SIZE)
        goto done;
    for (i = sz; i < SEFS_CHUNK_SIZE; i++)
        if (plain[CONTENT_OFF + i] != SEFS_PAD_BYTE)
            goto done;
    memcpy(content, plain + CONTENT_OFF, sz);
    *size = sz;
    ok = 1;
done:
    OPENSSL_cleanse(plain, sizeof plain);
    free(file);
    return ok ? SEFS_OK : SEFS_ERR;
}

int chunk_delete(const char *name)
{
    char path[256];
    if (chunk_path(name, path, sizeof path) != SEFS_OK)
        return SEFS_ERR;
    return remove(path) == 0 ? SEFS_OK : SEFS_ERR;
}
