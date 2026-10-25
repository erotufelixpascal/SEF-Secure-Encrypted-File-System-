#ifndef SEFS_H
#define SEFS_H

#include "sefs_api.h"
#include "auth.h"

/*
 * Parts 2-3. Each function authenticates u/p against SEFS_PASSWD_FILE and,
 * for a single file, checks that u owns it. Returns 1 (OKAY) or -1 (ERROR)
 * unless noted. Signatures are placeholders until the lecturer's header is
 * confirmed (README, Step 2).
 */
SEFS_API int create_file(const char *filename, const char *u, const char *p);
SEFS_API int encrypt_file(const char *filename, const char *u, const char *p);
SEFS_API int decrypt_file(const char *filename, const char *pfilename, const char *u, const char *p);
/* Returns len bytes from position as a NUL-terminated buffer (free with sefs_free), NULL on error. */
SEFS_API char *read_from_file(const char *filename, int position, int len, const char *u, const char *p);
/* Inserts content at position (0..size); later content shifts forward. */
SEFS_API int write_to_file(const char *filename, int position, const char *content, const char *u, const char *p);
/* File size in bytes, or -1. */
SEFS_API long file_size(const char *filename, const char *u, const char *p);
SEFS_API int file_integrity_check(const char *filename, const char *u, const char *p);
SEFS_API int delete_file(const char *filename, const char *u, const char *p);
/* Integrity-checks every file in the Master File List. */
SEFS_API int system_health_check(const char *u, const char *p);

SEFS_API void sefs_free(void *ptr);

#endif
