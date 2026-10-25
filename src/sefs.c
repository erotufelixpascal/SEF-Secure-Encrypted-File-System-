#include "sefs.h"
#include "chunk.h"
#include "meta.h"
#include "sefs_config.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

static int valid_filename(const char *f)
{
    size_t i, n;
    if (f == NULL || (n = strlen(f)) == 0 || n > SEFS_FILENAME_MAX)
        return 0;
    for (i = 0; i < n; i++)
        if (!isalnum((unsigned char)f[i]) || (unsigned char)f[i] >= 0x80)
            return 0;
    return 1;
}

static void free_secret(unsigned char *buf, size_t len)
{
    if (buf != NULL) {
        OPENSSL_cleanse(buf, len);
        free(buf);
    }
}

/* Loads the meta of a registered file; checks its Master File List digest (if asked) and that u owns it. */
static int load_checked_meta(const char *filename, const char *owner, int check_digest, sefs_meta *m)
{
    unsigned char want[SEFS_DIGEST_LEN], got[SEFS_DIGEST_LEN];

    memset(m, 0, sizeof *m);
    if (masterlist_get(filename, want) != 1 || meta_load(filename, m, got) != SEFS_OK)
        return SEFS_ERR;
    if ((check_digest && CRYPTO_memcmp(want, got, SEFS_DIGEST_LEN) != 0) ||
        (owner != NULL && strcmp(m->owner, owner) != 0)) {
        meta_free(m);
        return SEFS_ERR;
    }
    return SEFS_OK;
}

static int authorize(const char *filename, const char *u, const char *p, int check_digest, sefs_meta *m)
{
    memset(m, 0, sizeof *m);
    if (!valid_filename(filename) || match_user(u, p, SEFS_PASSWD_FILE) != SEFS_OK)
        return SEFS_ERR;
    return load_checked_meta(filename, u, check_digest, m);
}

/*
 * Walks the chain from the start chunk, verifying every chunk HMAC, next-chunk link,
 * the chunk-count rule and the total size, and returns the whole plaintext.
 */
static int verify_chain(const sefs_meta *m, unsigned char **out, size_t *outlen)
{
    unsigned char content[SEFS_CHUNK_SIZE], *buf;
    char next[SEFS_CHUNK_NAME_LEN + 1];
    size_t sz, total = 0;
    int i, n = m->nchunks, expect;

    *out = NULL;
    *outlen = 0;
    if (m->size < 0 || m->size > SEFS_MAX_FILE_SIZE)
        return SEFS_ERR;
    expect = m->size == 0 ? 1 : (int)((m->size + SEFS_CHUNK_SIZE - 1) / SEFS_CHUNK_SIZE);
    if (n != expect || strcmp(m->start, m->chunks[0].name) != 0 || strcmp(m->end, m->chunks[n - 1].name) != 0)
        return SEFS_ERR;
    if ((buf = malloc((size_t)m->size + 1)) == NULL)
        return SEFS_ERR;
    for (i = 0; i < n; i++) {
        if (chunk_read(&m->chunks[i], content, &sz, next) != SEFS_OK)
            goto fail;
        if (i + 1 < n) {
            if (sz != SEFS_CHUNK_SIZE || strcmp(next, m->chunks[i + 1].name) != 0)
                goto fail;
        } else if (next[0] != '\0') {
            goto fail;
        }
        if (total + sz > (size_t)m->size)
            goto fail;
        memcpy(buf + total, content, sz);
        total += sz;
    }
    if (total != (size_t)m->size)
        goto fail;
    buf[total] = '\0';
    OPENSSL_cleanse(content, sizeof content);
    *out = buf;
    *outlen = total;
    return SEFS_OK;
fail:
    OPENSSL_cleanse(content, sizeof content);
    free_secret(buf, (size_t)m->size + 1);
    return SEFS_ERR;
}

/*
 * Splits data into the minimum number of chunks, encrypts each with a fresh key and IV,
 * writes the meta file and Master File List entry, and only then removes the old chunks.
 */
static int store_plaintext(const char *filename, const char *owner, const unsigned char *data, size_t len,
                           const sefs_meta *old)
{
    sefs_meta m;
    char (*names)[SEFS_CHUNK_NAME_LEN + 1] = NULL;
    int n, i, written = 0, ok = 0;

    if (len > (size_t)SEFS_MAX_FILE_SIZE)
        return SEFS_ERR;
    n = len == 0 ? 1 : (int)((len + SEFS_CHUNK_SIZE - 1) / SEFS_CHUNK_SIZE);
    memset(&m, 0, sizeof m);
    names = calloc((size_t)n, sizeof *names);
    m.chunks = calloc((size_t)n, sizeof *m.chunks);
    if (names == NULL || m.chunks == NULL || ensure_dir(SEFS_CHUNK_DIR) != SEFS_OK)
        goto done;
    for (i = 0; i < n; i++)
        if (chunk_new_name(names[i]) != SEFS_OK)
            goto done;
    for (i = 0; i < n; i++) {
        size_t off = (size_t)i * SEFS_CHUNK_SIZE;
        size_t sz = len - off < SEFS_CHUNK_SIZE ? len - off : SEFS_CHUNK_SIZE;
        if (chunk_write(names[i], i + 1 < n ? names[i + 1] : NULL, sz ? data + off : NULL, sz,
                        &m.chunks[i]) != SEFS_OK)
            goto done;
        written++;
    }
    strcpy(m.owner, owner);
    m.nchunks = n;
    m.size = (long)len;
    strcpy(m.start, names[0]);
    strcpy(m.end, names[n - 1]);
    if (meta_save(filename, &m) != SEFS_OK)
        goto done;
    ok = 1;
    if (old != NULL)
        for (i = 0; i < old->nchunks; i++)
            chunk_delete(old->chunks[i].name);
done:
    if (!ok)
        for (i = 0; i < written; i++)
            chunk_delete(names[i]);
    if (m.chunks != NULL) {
        OPENSSL_cleanse(m.chunks, (size_t)n * sizeof *m.chunks);
        free(m.chunks);
    }
    free(names);
    return ok ? SEFS_OK : SEFS_ERR;
}

SEFS_API int create_file(const char *filename, const char *u, const char *p)
{
    unsigned char d[SEFS_DIGEST_LEN];
    char path[256];

    if (!valid_filename(filename) || match_user(u, p, SEFS_PASSWD_FILE) != SEFS_OK)
        return SEFS_ERR;
    if (masterlist_get(filename, d) != 0 || meta_path(filename, path, sizeof path) != SEFS_OK ||
        file_exists(path))
        return SEFS_ERR;
    return store_plaintext(filename, u, NULL, 0, NULL);
}

SEFS_API int encrypt_file(const char *filename, const char *u, const char *p)
{
    unsigned char d[SEFS_DIGEST_LEN], *data;
    char path[256];
    size_t len;
    sefs_meta old;
    int registered, r;

    memset(&old, 0, sizeof old);
    if (!valid_filename(filename) || match_user(u, p, SEFS_PASSWD_FILE) != SEFS_OK)
        return SEFS_ERR;
    if ((registered = masterlist_get(filename, d)) < 0)
        return SEFS_ERR;
    if (registered) {
        /* Re-encrypting replaces the content; only the owner may do that. */
        if (load_checked_meta(filename, u, 0, &old) != SEFS_OK)
            return SEFS_ERR;
    } else if (meta_path(filename, path, sizeof path) != SEFS_OK || file_exists(path)) {
        return SEFS_ERR;
    }
    if (read_all(filename, &data, &len) != SEFS_OK) {
        meta_free(&old);
        return SEFS_ERR;
    }
    r = store_plaintext(filename, u, data, len, registered ? &old : NULL);
    free_secret(data, len);
    meta_free(&old);
    if (r == SEFS_OK && SEFS_REMOVE_PLAINTEXT)
        remove(filename);
    return r;
}

SEFS_API int decrypt_file(const char *filename, const char *pfilename, const char *u, const char *p)
{
    unsigned char *buf;
    size_t len;
    sefs_meta m;
    int r;

    if (pfilename == NULL || pfilename[0] == '\0')
        return SEFS_ERR;
    if (authorize(filename, u, p, 1, &m) != SEFS_OK)
        return SEFS_ERR;
    r = verify_chain(&m, &buf, &len);
    meta_free(&m);
    if (r != SEFS_OK)
        return SEFS_ERR;
    r = write_atomic(pfilename, buf, len);
    free_secret(buf, len + 1);
    return r;
}

SEFS_API char *read_from_file(const char *filename, int position, int len, const char *u, const char *p)
{
    unsigned char *buf;
    char *out = NULL;
    size_t n;
    sefs_meta m;
    int r;

    if (position < 0 || len < 0)
        return NULL;
    if (authorize(filename, u, p, 1, &m) != SEFS_OK)
        return NULL;
    r = verify_chain(&m, &buf, &n);
    meta_free(&m);
    if (r != SEFS_OK)
        return NULL;
    if ((size_t)position <= n && (size_t)len <= n - (size_t)position &&
        (out = malloc((size_t)len + 1)) != NULL) {
        memcpy(out, buf + position, (size_t)len);
        out[len] = '\0';
    }
    free_secret(buf, n + 1);
    return out;
}

SEFS_API int write_to_file(const char *filename, int position, const char *content, const char *u, const char *p)
{
    unsigned char *buf, *nb = NULL;
    size_t n, clen;
    sefs_meta m;
    int r = SEFS_ERR;

    if (content == NULL || position < 0)
        return SEFS_ERR;
    clen = strlen(content);
    if (authorize(filename, u, p, 1, &m) != SEFS_OK)
        return SEFS_ERR;
    if (verify_chain(&m, &buf, &n) != SEFS_OK) {
        meta_free(&m);
        return SEFS_ERR;
    }
    if ((size_t)position > n || n + clen > (size_t)SEFS_MAX_FILE_SIZE)
        goto done;
    if (clen == 0) {
        r = SEFS_OK;
        goto done;
    }
    if ((nb = malloc(n + clen)) == NULL)
        goto done;
    memcpy(nb, buf, (size_t)position);
    memcpy(nb + position, content, clen);
    memcpy(nb + position + clen, buf + position, n - (size_t)position);
    r = store_plaintext(filename, u, nb, n + clen, &m);
done:
    free_secret(nb, n + clen);
    free_secret(buf, n + 1);
    meta_free(&m);
    return r;
}

SEFS_API long file_size(const char *filename, const char *u, const char *p)
{
    sefs_meta m;
    long size;

    if (authorize(filename, u, p, 1, &m) != SEFS_OK)
        return SEFS_ERR;
    size = m.size;
    meta_free(&m);
    return size;
}

SEFS_API int file_integrity_check(const char *filename, const char *u, const char *p)
{
    unsigned char *buf;
    size_t n;
    sefs_meta m;
    int r;

    if (authorize(filename, u, p, 1, &m) != SEFS_OK)
        return SEFS_ERR;
    r = verify_chain(&m, &buf, &n);
    meta_free(&m);
    if (r == SEFS_OK)
        free_secret(buf, n + 1);
    return r;
}

SEFS_API int delete_file(const char *filename, const char *u, const char *p)
{
    char path[256];
    sefs_meta m;
    int i;

    /* No digest check: an owner may still delete a file whose meta digest was tampered with. */
    if (authorize(filename, u, p, 0, &m) != SEFS_OK)
        return SEFS_ERR;
    for (i = 0; i < m.nchunks; i++)
        chunk_delete(m.chunks[i].name);
    meta_free(&m);
    if (meta_path(filename, path, sizeof path) != SEFS_OK || remove(path) != 0)
        return SEFS_ERR;
    return masterlist_put(filename, NULL);
}

SEFS_API int system_health_check(const char *u, const char *p)
{
    char **names;
    int count, i, healthy = 1;

    if (match_user(u, p, SEFS_PASSWD_FILE) != SEFS_OK)
        return SEFS_ERR;
    if (masterlist_names(&names, &count) != SEFS_OK)
        return SEFS_ERR;
    for (i = 0; i < count; i++) {
        unsigned char *buf;
        size_t n;
        sefs_meta m;
        if (!valid_filename(names[i]) || load_checked_meta(names[i], NULL, 1, &m) != SEFS_OK) {
            healthy = 0;
            continue;
        }
        if (verify_chain(&m, &buf, &n) == SEFS_OK)
            free_secret(buf, n + 1);
        else
            healthy = 0;
        meta_free(&m);
    }
    masterlist_free_names(names, count);
    return healthy ? SEFS_OK : SEFS_ERR;
}

SEFS_API void sefs_free(void *ptr)
{
    free(ptr);
}
