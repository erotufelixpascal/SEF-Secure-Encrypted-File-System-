#ifndef SEFS_UTIL_H
#define SEFS_UTIL_H

#include <stddef.h>

/* Binary-mode file helpers. All return SEFS_OK or SEFS_ERR unless noted. */
int read_all(const char *path, unsigned char **buf, size_t *len); /* *buf is NUL-terminated, caller frees */
int write_atomic(const char *path, const unsigned char *buf, size_t len); /* temp file + replace */
int replace_file(const char *tmp, const char *target);
int file_exists(const char *path); /* 1 or 0 */
int ensure_dir(const char *path);

void to_hex(const unsigned char *in, size_t n, char *out); /* out holds 2n+1 chars */
int from_hex(const char *in, size_t inlen, unsigned char *out, size_t n); /* accepts either case */
int is_hex_string(const char *s, size_t n);

int load_master_key(unsigned char *key, unsigned char *iv);
int meta_path(const char *filename, char *out, size_t n);
int chunk_path(const char *name, char *out, size_t n);

#endif
