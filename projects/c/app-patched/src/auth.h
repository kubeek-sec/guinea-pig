/* Member sessions: bearer tokens signed with the instance key. */
#ifndef TOOLSHED_AUTH_H
#define TOOLSHED_AUTH_H

#include <stdbool.h>

#include "store.h"

#define TOOLSHED_TOKEN_MAX 1024

bool auth_issue(const member_t *member, char *out, size_t out_size);
bool auth_authenticate(const char *email, const char *password, member_t *out);
bool auth_from_header(const char *authorization, member_t *out);

#endif
