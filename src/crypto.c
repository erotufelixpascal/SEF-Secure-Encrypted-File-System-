#include "crypto.h"
#include "sefs_config.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

int gen_random(unsigned char *buf, int n)
{
    return RAND_bytes(buf, n) == 1 ? SEFS_OK : SEFS_ERR;
}

int aes128_ctr(const unsigned char *k, const unsigned char *iv,
               const unsigned char *in, int len, unsigned char *out)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n, f, ok = SEFS_ERR;
    if (c && EVP_EncryptInit_ex(c, EVP_aes_128_ctr(), NULL, k, iv) == 1 &&
        EVP_EncryptUpdate(c, out, &n, in, len) == 1 &&
        EVP_EncryptFinal_ex(c, out + n, &f) == 1)
        ok = SEFS_OK;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

int hmac_sha256(const unsigned char *key, const unsigned char *data, size_t len, unsigned char *out)
{
    unsigned int outlen = 0;
    if (HMAC(EVP_sha256(), key, SEFS_KEY_LEN, data, len, out, &outlen) == NULL)
        return SEFS_ERR;
    return outlen == SEFS_HMAC_LEN ? SEFS_OK : SEFS_ERR;
}

int sha256(const unsigned char *data, size_t len, unsigned char *out)
{
    return SHA256(data, len, out) != NULL ? SEFS_OK : SEFS_ERR;
}
