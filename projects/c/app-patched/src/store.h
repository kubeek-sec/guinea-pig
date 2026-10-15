/* SQLite access layer and the initial dataset of the workshop. */
#ifndef TOOLSHED_STORE_H
#define TOOLSHED_STORE_H

#include <stdbool.h>

#include <sqlite3.h>

#include "jsonbuf.h"

#define TOOLSHED_NAME_MAX  64
#define TOOLSHED_TEXT_MAX  256
#define TOOLSHED_EMAIL_MAX 128
#define TOOLSHED_DATE_MAX  11
#define TOOLSHED_HASH_MAX  128

typedef struct {
    long long id;
    char      name[TOOLSHED_NAME_MAX];
    char      category[TOOLSHED_NAME_MAX];
    char      description[TOOLSHED_TEXT_MAX];
    double    daily_rate;
    bool      available;
} tool_t;

typedef struct {
    long long id;
    char      email[TOOLSHED_EMAIL_MAX];
    char      full_name[TOOLSHED_NAME_MAX];
    char      password[TOOLSHED_HASH_MAX];
    char      role[16];
} member_t;

typedef struct {
    long long id;
    long long member_id;
    long long tool_id;
    char      tool_name[TOOLSHED_NAME_MAX];
    char      taken_on[TOOLSHED_DATE_MAX];
    char      due_on[TOOLSHED_DATE_MAX];
    char      notes[TOOLSHED_TEXT_MAX];
    bool      returned;
} rental_t;

int  store_open(const char *file);
void store_close(void);

/* Each list_* call appends a JSON array to `out`. */
int  store_tools_ordered_by(const char *column, buf_t *out);
int  store_top_tools(int limit, buf_t *out);
int  store_search_tools(const char *term, buf_t *out);
int  store_rentals_of(long long member_id, buf_t *out);

bool store_tool(long long id, tool_t *out);
bool store_member_by_email(const char *email, member_t *out);
bool store_member(long long id, member_t *out);
bool store_rental_of(long long rental_id, long long member_id, rental_t *out);

long long store_create_rental(long long member_id, long long tool_id, const char *taken_on,
                              const char *due_on, const char *notes);
void store_set_tool_available(long long tool_id, bool available);
void store_close_rental(long long rental_id);

void tool_to_json(const tool_t *tool, buf_t *out);

char *store_hash_password(const char *password);
bool  store_check_password(const char *password, const char *expected);

#endif
