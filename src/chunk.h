#ifndef SEFS_CHUNK_H
#define SEFS_CHUNK_H

#include <stddef.h>
#include "sefs_config.h"

/* One "name - key - HMAC" line of a meta file. */
typedef struct {
    char name[SEFS_CHUNK_NAME_LEN + 1];
    unsigned char key[SEFS_KEY_LEN];
    unsigned char hmac[SEFS_HMAC_LEN];
} chunk_ref;

/* Picks a random chunk name not already on disk. */
int chunk_new_name(char *out);

/* Encrypts `size` bytes (<= SEFS_CHUNK_SIZE) under a fresh key and IV and writes chunk `name`.
 * `next` is the next chunk's name, or NULL for the last chunk. Fills ref with name, key and HMAC. */
int chunk_write(const char *name, const char *next, const unsigned char *data, size_t size, chunk_ref *ref);

/* Verifies the HMAC first, then decrypts. content holds SEFS_CHUNK_SIZE bytes;
 * next receives the next chunk name, or "" for the last chunk. */
int chunk_read(const chunk_ref *ref, unsigned char *content, size_t *size, char *next);

int chunk_delete(const char *name);

#endif
