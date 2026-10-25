#include "meta.h"
#include "crypto.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#define MAX_CHUNKS ((int)(SEFS_MAX_FILE_SIZE / SEFS_CHUNK_SIZE) + 1)
#define CHUNK_LINE_LEN (SEFS_CHUNK_NAME_LEN + 1 + 2 * SEFS_KEY_LEN + 1 + 2 * SEFS_HMAC_LEN)

/* Splits off the next '\n'-terminated line; NULL if none is left. */
static char *next_line(char **cur)
{
    char *line = *cur, *nl = strchr(line, '\n');
    if (nl == NULL)
        return NULL;
    *nl = '\0';
    *cur = nl + 1;
    return line;
}

static int parse_long(const char *s, long *out)
{
    size_t i, n = strlen(s);
    if (n == 0 || n > 10)
        return SEFS_ERR;
    for (i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9')
            return SEFS_ERR;
    *out = strtol(s, NULL, 10);
    return SEFS_OK;
}

static int parse_name(const char *s, char *out)
{
    if (strlen(s) != SEFS_CHUNK_NAME_LEN || !is_hex_string(s, SEFS_CHUNK_NAME_LEN))
        return SEFS_ERR;
    memcpy(out, s, SEFS_CHUNK_NAME_LEN + 1);
    return SEFS_OK;
}

static int meta_parse(char *text, sefs_meta *m)
{
    char *cur = text, *line;
    long v;
    int i;

    if ((line = next_line(&cur)) == NULL || strlen(line) == 0 || strlen(line) > SEFS_USER_MAX)
        return SEFS_ERR;
    strcpy(m->owner, line);
    if ((line = next_line(&cur)) == NULL || parse_long(line, &v) != SEFS_OK || v < 1 || v > MAX_CHUNKS)
        return SEFS_ERR;
    m->nchunks = (int)v;
    if ((line = next_line(&cur)) == NULL || parse_long(line, &v) != SEFS_OK || v > SEFS_MAX_FILE_SIZE)
        return SEFS_ERR;
    m->size = v;
    if ((line = next_line(&cur)) == NULL || parse_name(line, m->start) != SEFS_OK)
        return SEFS_ERR;
    if ((line = next_line(&cur)) == NULL || parse_name(line, m->end) != SEFS_OK)
        return SEFS_ERR;

    if ((m->chunks = calloc((size_t)m->nchunks, sizeof *m->chunks)) == NULL)
        return SEFS_ERR;
    for (i = 0; i < m->nchunks; i++) {
        chunk_ref *c = &m->chunks[i];
        if ((line = next_line(&cur)) == NULL || strlen(line) != CHUNK_LINE_LEN ||
            line[SEFS_CHUNK_NAME_LEN] != ' ' || line[SEFS_CHUNK_NAME_LEN + 1 + 2 * SEFS_KEY_LEN] != ' ')
            return SEFS_ERR;
        line[SEFS_CHUNK_NAME_LEN] = '\0';
        if (parse_name(line, c->name) != SEFS_OK ||
            from_hex(line + SEFS_CHUNK_NAME_LEN + 1, 2 * SEFS_KEY_LEN, c->key, SEFS_KEY_LEN) != SEFS_OK ||
            from_hex(line + SEFS_CHUNK_NAME_LEN + 2 + 2 * SEFS_KEY_LEN, 2 * SEFS_HMAC_LEN,
                     c->hmac, SEFS_HMAC_LEN) != SEFS_OK)
            return SEFS_ERR;
    }
    return *cur == '\0' ? SEFS_OK : SEFS_ERR;
}

void meta_free(sefs_meta *m)
{
    if (m->chunks != NULL) {
        OPENSSL_cleanse(m->chunks, (size_t)m->nchunks * sizeof *m->chunks);
        free(m->chunks);
    }
    memset(m, 0, sizeof *m);
}

int meta_load(const char *filename, sefs_meta *m, unsigned char *digest)
{
    unsigned char key[SEFS_KEY_LEN], iv[SEFS_IV_LEN], *ct = NULL, *pt = NULL;
    char path[256];
    size_t len;
    int ok = 0;

    memset(m, 0, sizeof *m);
    if (meta_path(filename, path, sizeof path) != SEFS_OK || read_all(path, &ct, &len) != SEFS_OK)
        return SEFS_ERR;
    if (len == 0 || len > (size_t)MAX_CHUNKS * 160 + 256)
        goto done;
    if (digest != NULL && sha256(ct, len, digest) != SEFS_OK)
        goto done;
    if (load_master_key(key, iv) != SEFS_OK || (pt = malloc(len + 1)) == NULL)
        goto done;
    if (aes128_ctr(key, iv, ct, (int)len, pt) != SEFS_OK)
        goto done;
    pt[len] = '\0';
    if (strlen((char *)pt) != len) /* embedded NUL: not a valid meta text */
        goto done;
    ok = meta_parse((char *)pt, m) == SEFS_OK;
done:
    if (pt != NULL) {
        OPENSSL_cleanse(pt, len);
        free(pt);
    }
    OPENSSL_cleanse(key, sizeof key);
    free(ct);
    if (!ok)
        meta_free(m);
    return ok ? SEFS_OK : SEFS_ERR;
}

int meta_save(const char *filename, const sefs_meta *m)
{
    unsigned char key[SEFS_KEY_LEN], iv[SEFS_IV_LEN], digest[SEFS_DIGEST_LEN], *ct = NULL;
    char *pt, path[256], keyhex[2 * SEFS_KEY_LEN + 1], machex[2 * SEFS_HMAC_LEN + 1];
    size_t cap = 256 + (size_t)m->nchunks * (CHUNK_LINE_LEN + 2), pos;
    int i, w, ok = 0;

    if ((pt = malloc(cap)) == NULL)
        return SEFS_ERR;
    w = snprintf(pt, cap, "%s\n%d\n%ld\n%s\n%s\n", m->owner, m->nchunks, m->size, m->start, m->end);
    if (w < 0 || (size_t)w >= cap)
        goto done;
    pos = (size_t)w;
    for (i = 0; i < m->nchunks; i++) {
        to_hex(m->chunks[i].key, SEFS_KEY_LEN, keyhex);
        to_hex(m->chunks[i].hmac, SEFS_HMAC_LEN, machex);
        w = snprintf(pt + pos, cap - pos, "%s %s %s\n", m->chunks[i].name, keyhex, machex);
        if (w < 0 || (size_t)w >= cap - pos)
            goto done;
        pos += (size_t)w;
    }
    if ((ct = malloc(pos)) == NULL || load_master_key(key, iv) != SEFS_OK)
        goto done;
    ok = aes128_ctr(key, iv, (unsigned char *)pt, (int)pos, ct) == SEFS_OK &&
         meta_path(filename, path, sizeof path) == SEFS_OK &&
         write_atomic(path, ct, pos) == SEFS_OK &&
         sha256(ct, pos, digest) == SEFS_OK &&
         masterlist_put(filename, digest) == SEFS_OK;
done:
    OPENSSL_cleanse(keyhex, sizeof keyhex);
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(pt, cap);
    free(pt);
    free(ct);
    return ok ? SEFS_OK : SEFS_ERR;
}

/* ---- Master File List: "filename sha256hex\n" per file ---- */

/* If line is a well-formed entry, NUL-terminates the name and returns a pointer to the digest hex. */
static char *split_entry(char *line)
{
    char *sp = strchr(line, ' ');
    if (sp == NULL || sp == line || strlen(sp + 1) != 2 * SEFS_DIGEST_LEN)
        return NULL;
    *sp = '\0';
    return sp + 1;
}

int masterlist_get(const char *filename, unsigned char *digest)
{
    unsigned char *buf;
    char *cur, *line, *hex;
    size_t len;
    int found = 0;

    if (!file_exists(SEFS_MASTER_LIST))
        return 0;
    if (read_all(SEFS_MASTER_LIST, &buf, &len) != SEFS_OK)
        return SEFS_ERR;
    cur = (char *)buf;
    while (found == 0 && (line = next_line(&cur)) != NULL) {
        if ((hex = split_entry(line)) != NULL && strcmp(line, filename) == 0)
            found = from_hex(hex, strlen(hex), digest, SEFS_DIGEST_LEN) == SEFS_OK ? 1 : SEFS_ERR;
    }
    free(buf);
    return found;
}

int masterlist_put(const char *filename, const unsigned char *digest)
{
    unsigned char *buf = NULL;
    char *out, *cur, *line, *hex, dhex[2 * SEFS_DIGEST_LEN + 1];
    size_t len = 0, pos = 0, cap;
    int r;

    if (file_exists(SEFS_MASTER_LIST) && read_all(SEFS_MASTER_LIST, &buf, &len) != SEFS_OK)
        return SEFS_ERR;
    cap = len + strlen(filename) + sizeof dhex + 4;
    if ((out = malloc(cap)) == NULL) {
        free(buf);
        return SEFS_ERR;
    }
    if (buf != NULL) {
        cur = (char *)buf;
        while ((line = next_line(&cur)) != NULL) {
            if ((hex = split_entry(line)) == NULL || strcmp(line, filename) == 0)
                continue; /* drop malformed lines and the old entry */
            pos += (size_t)sprintf(out + pos, "%s %s\n", line, hex);
        }
    }
    if (digest != NULL) {
        to_hex(digest, SEFS_DIGEST_LEN, dhex);
        pos += (size_t)sprintf(out + pos, "%s %s\n", filename, dhex);
    }
    r = write_atomic(SEFS_MASTER_LIST, (unsigned char *)out, pos);
    free(out);
    free(buf);
    return r;
}

int masterlist_names(char ***names, int *count)
{
    unsigned char *buf;
    char *cur, *line, **list = NULL;
    size_t len;
    int n = 0, cap = 0, ok = 1;

    *names = NULL;
    *count = 0;
    if (!file_exists(SEFS_MASTER_LIST))
        return SEFS_OK;
    if (read_all(SEFS_MASTER_LIST, &buf, &len) != SEFS_OK)
        return SEFS_ERR;
    cur = (char *)buf;
    while (ok && (line = next_line(&cur)) != NULL) {
        if (split_entry(line) == NULL) {
            ok = 0; /* a malformed list is itself an integrity failure */
            break;
        }
        if (n == cap) {
            char **grown = realloc(list, (size_t)(cap = cap ? cap * 2 : 16) * sizeof *list);
            if (grown == NULL) {
                ok = 0;
                break;
            }
            list = grown;
        }
        if ((list[n] = malloc(strlen(line) + 1)) == NULL) {
            ok = 0;
            break;
        }
        strcpy(list[n++], line);
    }
    if (*cur != '\0')
        ok = 0;
    free(buf);
    if (!ok) {
        masterlist_free_names(list, n);
        return SEFS_ERR;
    }
    *names = list;
    *count = n;
    return SEFS_OK;
}

void masterlist_free_names(char **names, int count)
{
    int i;
    for (i = 0; i < count; i++)
        free(names[i]);
    free(names);
}
