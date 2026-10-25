#include "auth.h"
#include "crypto.h"
#include "sefs_config.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define LINE_MAX_LEN 512

static int valid_string(const char *s, size_t min, size_t max, const char *extra)
{
    size_t i, n;
    if (s == NULL)
        return 0;
    n = strlen(s);
    if (n < min || n > max)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) && c < 0x80) && (extra == NULL || strchr(extra, c) == NULL))
            return 0;
    }
    return 1;
}

int valid_username(const char *u)
{
    return valid_string(u, SEFS_USER_MIN, SEFS_USER_MAX, NULL);
}

int valid_password(const char *p)
{
    return valid_string(p, SEFS_PASS_MIN, SEFS_PASS_MAX, SEFS_PASS_EXTRA);
}

static int hash_password(const char *p, const unsigned char *salt, unsigned char *hash)
{
    return PKCS5_PBKDF2_HMAC_SHA1(p, (int)strlen(p), salt, SEFS_SALT_LEN,
                                  SEFS_PBKDF2_ITER, SEFS_HASH_LEN, hash) == 1 ? SEFS_OK : SEFS_ERR;
}

/* Strips the line ending and returns the length of the username field, or 0 if malformed. */
static size_t line_user_len(char *line)
{
    char *colon;
    line[strcspn(line, "\r\n")] = '\0';
    colon = strchr(line, ':');
    return colon ? (size_t)(colon - line) : 0;
}

static int line_is_user(char *line, const char *u)
{
    size_t n = line_user_len(line);
    return n > 0 && n == strlen(u) && strncmp(line, u, n) == 0;
}

/* Returns 1 and fills salt/hash if u is in pFile, 0 if not, SEFS_ERR on a malformed entry. */
static int find_user(const char *u, const char *pFile, unsigned char *salt, unsigned char *hash)
{
    char line[LINE_MAX_LEN];
    FILE *f;
    int found = 0;

    if ((f = fopen(pFile, "rb")) == NULL)
        return 0;
    while (fgets(line, sizeof line, f) != NULL) {
        char *salthex, *hashhex;
        if (!line_is_user(line, u))
            continue;
        salthex = line + strlen(u) + 1;
        hashhex = strchr(salthex, ':');
        found = SEFS_ERR;
        if (hashhex != NULL) {
            *hashhex++ = '\0';
            if (from_hex(salthex, strlen(salthex), salt, SEFS_SALT_LEN) == SEFS_OK &&
                from_hex(hashhex, strlen(hashhex), hash, SEFS_HASH_LEN) == SEFS_OK)
                found = 1;
        }
        break;
    }
    fclose(f);
    OPENSSL_cleanse(line, sizeof line);
    return found;
}

/* Builds "u:salthex:hashhex\n" with a fresh salt. */
static int make_entry(const char *u, const char *p, char *out, size_t outlen)
{
    unsigned char salt[SEFS_SALT_LEN], hash[SEFS_HASH_LEN];
    char salthex[2 * SEFS_SALT_LEN + 1], hashhex[2 * SEFS_HASH_LEN + 1];
    int ok;

    ok = gen_random(salt, SEFS_SALT_LEN) == SEFS_OK && hash_password(p, salt, hash) == SEFS_OK;
    if (ok) {
        to_hex(salt, SEFS_SALT_LEN, salthex);
        to_hex(hash, SEFS_HASH_LEN, hashhex);
        ok = snprintf(out, outlen, "%s:%s:%s\n", u, salthex, hashhex) < (int)outlen;
    }
    OPENSSL_cleanse(hash, sizeof hash);
    return ok ? SEFS_OK : SEFS_ERR;
}

/* Copies pFile to a temp file, replacing u's line with `entry` (or dropping it if NULL), then swaps it in. */
static int rewrite_user(const char *u, const char *entry, const char *pFile)
{
    char line[LINE_MAX_LEN], tmp[512];
    FILE *in, *out;
    int ok = 1;

    if (snprintf(tmp, sizeof tmp, "%s.tmp", pFile) >= (int)sizeof tmp)
        return SEFS_ERR;
    if ((in = fopen(pFile, "rb")) == NULL)
        return SEFS_ERR;
    if ((out = fopen(tmp, "wb")) == NULL) {
        fclose(in);
        return SEFS_ERR;
    }
    while (ok && fgets(line, sizeof line, in) != NULL) {
        char copy[LINE_MAX_LEN];
        memcpy(copy, line, sizeof line);
        if (line_is_user(copy, u)) {
            if (entry != NULL)
                ok = fputs(entry, out) >= 0;
        } else {
            ok = fputs(line, out) >= 0;
        }
    }
    if (ferror(in) || fflush(out) != 0)
        ok = 0;
    fclose(in);
    if (fclose(out) != 0)
        ok = 0;
    if (!ok || replace_file(tmp, pFile) != SEFS_OK) {
        remove(tmp);
        return SEFS_ERR;
    }
    return SEFS_OK;
}

SEFS_API int register_user(const char *u, const char *p, const char *pFile)
{
    unsigned char salt[SEFS_SALT_LEN], hash[SEFS_HASH_LEN];
    char entry[LINE_MAX_LEN];
    FILE *f;
    int ok;

    if (!valid_username(u) || !valid_password(p) || pFile == NULL || pFile[0] == '\0')
        return SEFS_ERR;
    if (find_user(u, pFile, salt, hash) != 0)
        return SEFS_ERR;
    if (make_entry(u, p, entry, sizeof entry) != SEFS_OK)
        return SEFS_ERR;
    if ((f = fopen(pFile, "ab")) == NULL)
        return SEFS_ERR;
    ok = fputs(entry, f) >= 0;
    if (fclose(f) != 0)
        ok = 0;
    return ok ? SEFS_OK : SEFS_ERR;
}

SEFS_API int is_user_valid(const char *u, const char *pFile)
{
    unsigned char salt[SEFS_SALT_LEN], hash[SEFS_HASH_LEN];
    if (!valid_username(u) || pFile == NULL)
        return SEFS_ERR;
    return find_user(u, pFile, salt, hash) == 1 ? SEFS_OK : SEFS_ERR;
}

SEFS_API int match_user(const char *u, const char *p, const char *pFile)
{
    unsigned char salt[SEFS_SALT_LEN], stored[SEFS_HASH_LEN], hash[SEFS_HASH_LEN];
    int ok;

    if (!valid_username(u) || !valid_password(p) || pFile == NULL)
        return SEFS_ERR;
    if (find_user(u, pFile, salt, stored) != 1)
        return SEFS_ERR;
    ok = hash_password(p, salt, hash) == SEFS_OK &&
         CRYPTO_memcmp(hash, stored, SEFS_HASH_LEN) == 0;
    OPENSSL_cleanse(hash, sizeof hash);
    OPENSSL_cleanse(stored, sizeof stored);
    return ok ? SEFS_OK : SEFS_ERR;
}

SEFS_API int delete_user(const char *u, const char *p, const char *pFile)
{
    if (match_user(u, p, pFile) != SEFS_OK)
        return SEFS_ERR;
    return rewrite_user(u, NULL, pFile);
}

SEFS_API int change_user_password(const char *u, const char *p, const char *pn, const char *pFile)
{
    char entry[LINE_MAX_LEN];
    int r;

    if (!valid_password(pn) || match_user(u, p, pFile) != SEFS_OK)
        return SEFS_ERR;
    if (make_entry(u, pn, entry, sizeof entry) != SEFS_OK)
        return SEFS_ERR;
    r = rewrite_user(u, entry, pFile);
    OPENSSL_cleanse(entry, sizeof entry);
    return r;
}
