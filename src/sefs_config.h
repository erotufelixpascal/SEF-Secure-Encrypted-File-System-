#ifndef SEFS_CONFIG_H
#define SEFS_CONFIG_H

/*
 * Every format decision lives here. Values marked TODO-confirm are
 * placeholders for the open specification points in Step 2 (README.md);
 * change them here once the lecturer answers, then rebuild.
 */

/* Return codes used by every public function */
#define SEFS_OK   1
#define SEFS_ERR -1

/* Files, relative to the current working directory */
#define SEFS_PASSWD_FILE     "passwd"
#define SEFS_MASTER_KEY_FILE "master.key" /* 16-byte key then 16-byte IV (TODO-confirm: lecturer's sample format) */
#define SEFS_MASTER_LIST     "masterlist"
#define SEFS_CHUNK_DIR       "chunks"
#define SEFS_META_EXT        ".meta"

/* Part 1: authentication */
#define SEFS_SALT_LEN    32
#define SEFS_HASH_LEN    20      /* PBKDF2-HMAC-SHA1 output length (TODO-confirm Q2) */
#define SEFS_PBKDF2_ITER 20000
#define SEFS_HEX_UPPER   0       /* 0 = lowercase hex when writing (TODO-confirm Q2); reading accepts both */
#define SEFS_USER_MIN    6
#define SEFS_USER_MAX    31      /* TODO-confirm Q8 */
#define SEFS_PASS_MIN    9
#define SEFS_PASS_MAX    31      /* TODO-confirm Q8 */
#define SEFS_PASS_EXTRA  "@#$%&*()-+="

/* Parts 2-3: file system */
#define SEFS_FILENAME_MAX     20
#define SEFS_MAX_FILE_SIZE    (64L * 1024 * 1024)
#define SEFS_KEY_LEN          16
#define SEFS_IV_LEN           16
#define SEFS_HMAC_LEN         32
#define SEFS_DIGEST_LEN       32
#define SEFS_CHUNK_SIZE       1024
#define SEFS_PAD_BYTE         0x00 /* "ASCII character 0": byte 0x00 or '0' (0x30)? (TODO-confirm Q1) */
#define SEFS_CHUNK_NAME_BYTES 16   /* random bytes; the name is their hex, 32 chars (TODO-confirm Q5) */
#define SEFS_CHUNK_NAME_LEN   (2 * SEFS_CHUNK_NAME_BYTES)
#define SEFS_NULL_NAME        "NULL"
#define SEFS_REMOVE_PLAINTEXT 0    /* encrypt_file deletes the plaintext afterwards? (TODO-confirm) */

/*
 * Chunk file layout (TODO-confirm Q3, Q5):
 *   IV (16 bytes, plaintext)
 *   AES-128-CTR(chunk key, IV) of:
 *     next chunk name   32 bytes, "NULL" + zero bytes for the last chunk
 *     content size       4 bytes, big-endian unsigned
 *     content         1024 bytes, padded with SEFS_PAD_BYTE
 * Chunk HMAC = HMAC-SHA256(chunk key, IV || ciphertext), i.e. over the whole chunk file.
 *
 * Meta file F.meta (TODO-confirm Q4): AES-128-CTR(master key, master IV) of the text
 *   owner\n chunk count\n file size\n start chunk\n end chunk\n
 *   then per chunk: name<space>keyhex<space>hmachex\n
 *
 * Master File List (TODO-confirm Q6): plaintext, one "filename<space>sha256hex\n" per file,
 *   where the digest is over the meta file bytes as stored (ciphertext).
 */
#define SEFS_NEXT_FIELD_LEN 32
#define SEFS_SIZE_FIELD_LEN 4
#define SEFS_BODY_LEN       (SEFS_NEXT_FIELD_LEN + SEFS_SIZE_FIELD_LEN + SEFS_CHUNK_SIZE)
#define SEFS_CHUNK_FILE_LEN (SEFS_IV_LEN + SEFS_BODY_LEN)

#if SEFS_NEXT_FIELD_LEN < SEFS_CHUNK_NAME_LEN
#error "next-chunk field must hold a full chunk name"
#endif

#endif
