#ifndef SEFS_CRYPTO_H
#define SEFS_CRYPTO_H

#include <stddef.h>

/* Thin OpenSSL wrappers. All return SEFS_OK or SEFS_ERR. */
int gen_random(unsigned char *buf, int n);
int aes128_ctr(const unsigned char *k, const unsigned char *iv,
               const unsigned char *in, int len, unsigned char *out); /* encrypt == decrypt */
int hmac_sha256(const unsigned char *key, const unsigned char *data, size_t len, unsigned char *out);
int sha256(const unsigned char *data, size_t len, unsigned char *out);

#endif
