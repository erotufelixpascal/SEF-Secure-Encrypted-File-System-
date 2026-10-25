#ifndef SEFS_AUTH_H
#define SEFS_AUTH_H

#include "sefs_api.h"

/* Part 1: each returns 1 (OKAY) or -1 (ERROR). */
SEFS_API int register_user(const char *u, const char *p, const char *pFile);
SEFS_API int delete_user(const char *u, const char *p, const char *pFile);
SEFS_API int is_user_valid(const char *u, const char *pFile);
SEFS_API int match_user(const char *u, const char *p, const char *pFile);
SEFS_API int change_user_password(const char *u, const char *p, const char *pn, const char *pFile);

int valid_username(const char *u); /* 1 or 0 */
int valid_password(const char *p); /* 1 or 0 */

#endif
