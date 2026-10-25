#ifndef SEFS_META_H
#define SEFS_META_H

#include "chunk.h"
#include "sefs_config.h"

typedef struct {
    char owner[SEFS_USER_MAX + 1];
    int nchunks;
    long size;
    char start[SEFS_CHUNK_NAME_LEN + 1];
    char end[SEFS_CHUNK_NAME_LEN + 1];
    chunk_ref *chunks; /* nchunks entries, in chain order */
} sefs_meta;

/* Reads and decrypts F.meta. If digest is not NULL it receives SHA-256 of the stored meta bytes. */
int meta_load(const char *filename, sefs_meta *m, unsigned char *digest);
/* Encrypts and atomically writes F.meta, then records its digest in the Master File List. */
int meta_save(const char *filename, const sefs_meta *m);
void meta_free(sefs_meta *m);

/* Master File List. get returns 1 if found, 0 if not, SEFS_ERR on error. */
int masterlist_get(const char *filename, unsigned char *digest);
int masterlist_put(const char *filename, const unsigned char *digest); /* digest NULL removes the entry */
int masterlist_names(char ***names, int *count);
void masterlist_free_names(char **names, int count);

#endif
