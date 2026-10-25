#include "util.h"
#include "sefs_config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/crypto.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define sefs_mkdir(p) _mkdir(p)
#else
#define sefs_mkdir(p) mkdir((p), 0700)
#endif

int read_all(const char *path, unsigned char **buf, size_t *len)
{
    FILE *f;
    long n;
    unsigned char *b;

    *buf = NULL;
    *len = 0;
    if ((f = fopen(path, "rb")) == NULL)
        return SEFS_ERR;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return SEFS_ERR;
    }
    if ((b = malloc((size_t)n + 1)) == NULL) {
        fclose(f);
        return SEFS_ERR;
    }
    if (n > 0 && fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        fclose(f);
        return SEFS_ERR;
    }
    fclose(f);
    b[n] = '\0';
    *buf = b;
    *len = (size_t)n;
    return SEFS_OK;
}

int replace_file(const char *tmp, const char *target)
{
#ifdef _WIN32
    return MoveFileExA(tmp, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? SEFS_OK : SEFS_ERR;
#else
    return rename(tmp, target) == 0 ? SEFS_OK : SEFS_ERR;
#endif
}

int write_atomic(const char *path, const unsigned char *buf, size_t len)
{
    char tmp[512];
    FILE *f;
    int ok;

    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp)
        return SEFS_ERR;
    if ((f = fopen(tmp, "wb")) == NULL)
        return SEFS_ERR;
    ok = (len == 0 || fwrite(buf, 1, len, f) == len) && fflush(f) == 0;
    if (fclose(f) != 0)
        ok = 0;
    if (!ok || replace_file(tmp, path) != SEFS_OK) {
        remove(tmp);
        return SEFS_ERR;
    }
    return SEFS_OK;
}

int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return (st.st_mode & S_IFDIR) ? SEFS_OK : SEFS_ERR;
    return sefs_mkdir(path) == 0 ? SEFS_OK : SEFS_ERR;
}

void to_hex(const unsigned char *in, size_t n, char *out)
{
    const char *d = SEFS_HEX_UPPER ? "0123456789ABCDEF" : "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int from_hex(const char *in, size_t inlen, unsigned char *out, size_t n)
{
    size_t i;
    if (inlen != 2 * n)
        return SEFS_ERR;
    for (i = 0; i < n; i++) {
        int hi = hexval(in[2 * i]), lo = hexval(in[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return SEFS_ERR;
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return SEFS_OK;
}

int is_hex_string(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    return 1;
}

int load_master_key(unsigned char *key, unsigned char *iv)
{
    unsigned char *buf;
    size_t len;
    int ok;

    if (read_all(SEFS_MASTER_KEY_FILE, &buf, &len) != SEFS_OK)
        return SEFS_ERR;
    ok = len == SEFS_KEY_LEN + SEFS_IV_LEN;
    if (ok) {
        memcpy(key, buf, SEFS_KEY_LEN);
        memcpy(iv, buf + SEFS_KEY_LEN, SEFS_IV_LEN);
    }
    OPENSSL_cleanse(buf, len);
    free(buf);
    return ok ? SEFS_OK : SEFS_ERR;
}

int meta_path(const char *filename, char *out, size_t n)
{
    return snprintf(out, n, "%s%s", filename, SEFS_META_EXT) < (int)n ? SEFS_OK : SEFS_ERR;
}

int chunk_path(const char *name, char *out, size_t n)
{
    return snprintf(out, n, "%s/%s", SEFS_CHUNK_DIR, name) < (int)n ? SEFS_OK : SEFS_ERR;
}
