#define _GNU_SOURCE

#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <crypt.h>

static sqlite3 *db = NULL;

static const char *DDL =
    "CREATE TABLE IF NOT EXISTS members ("
    "    id        INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    email     TEXT UNIQUE NOT NULL,"
    "    full_name TEXT NOT NULL,"
    "    password  TEXT NOT NULL,"
    "    role      TEXT NOT NULL DEFAULT 'member');"
    "CREATE TABLE IF NOT EXISTS tools ("
    "    id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    name        TEXT NOT NULL,"
    "    category    TEXT NOT NULL,"
    "    description TEXT NOT NULL DEFAULT '',"
    "    daily_rate  REAL NOT NULL DEFAULT 0,"
    "    available   INTEGER NOT NULL DEFAULT 1);"
    "CREATE TABLE IF NOT EXISTS rentals ("
    "    id        INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    member_id INTEGER NOT NULL REFERENCES members(id),"
    "    tool_id   INTEGER NOT NULL REFERENCES tools(id),"
    "    taken_on  TEXT NOT NULL,"
    "    due_on    TEXT NOT NULL,"
    "    notes     TEXT NOT NULL DEFAULT '',"
    "    returned  INTEGER NOT NULL DEFAULT 0);";

static const struct {
    const char *name;
    const char *category;
    const char *description;
    double      rate;
} SEED_TOOLS[] = {
    {"Circular saw",  "cutting",   "190 mm blade, 1400 W",    12.5},
    {"Impact driver", "drilling",  "18 V, two batteries",      8.0},
    {"Mitre saw",     "cutting",   "Sliding, 255 mm",         18.0},
    {"Heat gun",      "finishing", "2000 W, variable",         5.5},
    {"Mortar mixer",  "masonry",   "1600 W, 140 mm paddle",   15.0},
};

static const struct {
    const char *email;
    const char *name;
    const char *password;
    const char *role;
} SEED_MEMBERS[] = {
    {"ada@toolshed.example",    "Ada Mallory",    "workshop-keeper", "staff"},
    {"jun@toolshed.example",    "Jun Watanabe",   "sawdust-season",  "member"},
    {"pierre@toolshed.example", "Pierre Lefranc", "bench-grinder",   "member"},
};

static void copy_text(char *dest, size_t size, const unsigned char *src)
{
    if (src == NULL) {
        dest[0] = '\0';
        return;
    }
    snprintf(dest, size, "%s", (const char *) src);
}

static void make_parent_dir(const char *file)
{
    char path[512];
    snprintf(path, sizeof path, "%s", file);
    char *slash = strrchr(path, '/');
    if (slash == NULL) {
        return;
    }
    *slash = '\0';
    for (char *p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(path, 0750);
            *p = '/';
        }
    }
    mkdir(path, 0750);
}

char *store_hash_password(const char *password)
{
    char salt[CRYPT_GENSALT_OUTPUT_SIZE];
    if (crypt_gensalt_rn("$2b$", 12, NULL, 0, salt, sizeof salt) == NULL) {
        return NULL;
    }
    struct crypt_data data;
    memset(&data, 0, sizeof data);
    char *hash = crypt_r(password, salt, &data);
    return hash ? strdup(hash) : NULL;
}

bool store_check_password(const char *password, const char *expected)
{
    struct crypt_data data;
    memset(&data, 0, sizeof data);
    char *hash = crypt_r(password, expected, &data);
    if (hash == NULL) {
        return false;
    }
    size_t len = strlen(expected);
    if (strlen(hash) != len) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char) (hash[i] ^ expected[i]);
    }
    return diff == 0;
}

static int seed(void)
{
    sqlite3_stmt *count = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM tools", -1, &count, NULL) != SQLITE_OK) {
        return -1;
    }
    long long rows = (sqlite3_step(count) == SQLITE_ROW) ? sqlite3_column_int64(count, 0) : 1;
    sqlite3_finalize(count);
    if (rows > 0) {
        return 0;
    }

    for (size_t i = 0; i < sizeof SEED_TOOLS / sizeof SEED_TOOLS[0]; i++) {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db,
            "INSERT INTO tools (name, category, description, daily_rate) VALUES (?1, ?2, ?3, ?4)",
            -1, &st, NULL);
        sqlite3_bind_text(st, 1, SEED_TOOLS[i].name, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, SEED_TOOLS[i].category, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 3, SEED_TOOLS[i].description, -1, SQLITE_STATIC);
        sqlite3_bind_double(st, 4, SEED_TOOLS[i].rate);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    for (size_t i = 0; i < sizeof SEED_MEMBERS / sizeof SEED_MEMBERS[0]; i++) {
        char *hash = store_hash_password(SEED_MEMBERS[i].password);
        if (hash == NULL) {
            return -1;
        }
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db,
            "INSERT INTO members (email, full_name, password, role) VALUES (?1, ?2, ?3, ?4)",
            -1, &st, NULL);
        sqlite3_bind_text(st, 1, SEED_MEMBERS[i].email, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, SEED_MEMBERS[i].name, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 3, hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, SEED_MEMBERS[i].role, -1, SQLITE_STATIC);
        sqlite3_step(st);
        sqlite3_finalize(st);
        free(hash);
    }
    return 0;
}

int store_open(const char *file)
{
    make_parent_dir(file);
    if (sqlite3_open(file, &db) != SQLITE_OK) {
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    char *message = NULL;
    if (sqlite3_exec(db, DDL, NULL, NULL, &message) != SQLITE_OK) {
        fprintf(stderr, "schema: %s\n", message ? message : "unknown");
        sqlite3_free(message);
        return -1;
    }
    return seed();
}

void store_close(void)
{
    sqlite3_close(db);
    db = NULL;
}

static void read_tool(sqlite3_stmt *st, tool_t *tool)
{
    tool->id = sqlite3_column_int64(st, 0);
    copy_text(tool->name, sizeof tool->name, sqlite3_column_text(st, 1));
    copy_text(tool->category, sizeof tool->category, sqlite3_column_text(st, 2));
    copy_text(tool->description, sizeof tool->description, sqlite3_column_text(st, 3));
    tool->daily_rate = sqlite3_column_double(st, 4);
    tool->available = sqlite3_column_int(st, 5) != 0;
}

void tool_to_json(const tool_t *tool, buf_t *out)
{
    buf_addf(out, "{\"id\":%lld,\"name\":", tool->id);
    buf_add_json_string(out, tool->name);
    buf_add(out, ",\"category\":");
    buf_add_json_string(out, tool->category);
    buf_add(out, ",\"description\":");
    buf_add_json_string(out, tool->description);
    buf_addf(out, ",\"daily_rate\":%.2f,\"available\":%s}",
             tool->daily_rate, tool->available ? "true" : "false");
}

static int collect_tools(sqlite3_stmt *st, buf_t *out)
{
    buf_add(out, "[");
    bool first = true;
    while (sqlite3_step(st) == SQLITE_ROW) {
        tool_t tool;
        read_tool(st, &tool);
        if (!first) {
            buf_add(out, ",");
        }
        first = false;
        tool_to_json(&tool, out);
    }
    buf_add(out, "]");
    return 0;
}

int store_tools_ordered_by(const char *column, buf_t *out)
{
    char sql[128];
    snprintf(sql, sizeof sql, "SELECT * FROM tools ORDER BY %s", column);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    collect_tools(st, out);
    sqlite3_finalize(st);
    return 0;
}

int store_top_tools(int limit, buf_t *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT * FROM tools ORDER BY name LIMIT ?1", -1, &st, NULL)
            != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(st, 1, limit);
    collect_tools(st, out);
    sqlite3_finalize(st);
    return 0;
}

int store_search_tools(const char *term, buf_t *out)
{
    char like[TOOLSHED_TEXT_MAX];
    snprintf(like, sizeof like, "%%%s%%", term ? term : "");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT * FROM tools WHERE name LIKE ?1 OR description LIKE ?1", -1, &st, NULL)
            != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(st, 1, like, -1, SQLITE_TRANSIENT);
    collect_tools(st, out);
    sqlite3_finalize(st);
    return 0;
}

bool store_tool(long long id, tool_t *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT * FROM tools WHERE id = ?1", -1, &st, NULL) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int64(st, 1, id);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    if (found) {
        read_tool(st, out);
    }
    sqlite3_finalize(st);
    return found;
}

static void read_member(sqlite3_stmt *st, member_t *member)
{
    member->id = sqlite3_column_int64(st, 0);
    copy_text(member->email, sizeof member->email, sqlite3_column_text(st, 1));
    copy_text(member->full_name, sizeof member->full_name, sqlite3_column_text(st, 2));
    copy_text(member->password, sizeof member->password, sqlite3_column_text(st, 3));
    copy_text(member->role, sizeof member->role, sqlite3_column_text(st, 4));
}

bool store_member_by_email(const char *email, member_t *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT * FROM members WHERE email = ?1", -1, &st, NULL)
            != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(st, 1, email, -1, SQLITE_STATIC);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    if (found) {
        read_member(st, out);
    }
    sqlite3_finalize(st);
    return found;
}

bool store_member(long long id, member_t *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT * FROM members WHERE id = ?1", -1, &st, NULL) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int64(st, 1, id);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    if (found) {
        read_member(st, out);
    }
    sqlite3_finalize(st);
    return found;
}

int store_rentals_of(long long member_id, buf_t *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT r.id, r.member_id, r.tool_id, r.taken_on, r.due_on, r.notes, r.returned,"
            "       t.name AS tool_name "
            "FROM rentals r JOIN tools t ON t.id = r.tool_id "
            "WHERE r.member_id = ?1 ORDER BY r.taken_on DESC", -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(st, 1, member_id);
    buf_add(out, "[");
    bool first = true;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (!first) {
            buf_add(out, ",");
        }
        first = false;
        buf_addf(out, "{\"id\":%lld,\"member_id\":%lld,\"tool_id\":%lld,\"tool_name\":",
                 sqlite3_column_int64(st, 0), sqlite3_column_int64(st, 1),
                 sqlite3_column_int64(st, 2));
        buf_add_json_string(out, (const char *) sqlite3_column_text(st, 7));
        buf_add(out, ",\"taken_on\":");
        buf_add_json_string(out, (const char *) sqlite3_column_text(st, 3));
        buf_add(out, ",\"due_on\":");
        buf_add_json_string(out, (const char *) sqlite3_column_text(st, 4));
        buf_add(out, ",\"notes\":");
        buf_add_json_string(out, (const char *) sqlite3_column_text(st, 5));
        buf_addf(out, ",\"returned\":%s}", sqlite3_column_int(st, 6) ? "true" : "false");
    }
    buf_add(out, "]");
    sqlite3_finalize(st);
    return 0;
}

bool store_rental_of(long long rental_id, long long member_id, rental_t *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT * FROM rentals WHERE id = ?1 AND member_id = ?2",
                           -1, &st, NULL) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int64(st, 1, rental_id);
    sqlite3_bind_int64(st, 2, member_id);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    if (found) {
        out->id = sqlite3_column_int64(st, 0);
        out->member_id = sqlite3_column_int64(st, 1);
        out->tool_id = sqlite3_column_int64(st, 2);
        out->tool_name[0] = '\0';
        copy_text(out->taken_on, sizeof out->taken_on, sqlite3_column_text(st, 3));
        copy_text(out->due_on, sizeof out->due_on, sqlite3_column_text(st, 4));
        copy_text(out->notes, sizeof out->notes, sqlite3_column_text(st, 5));
        out->returned = sqlite3_column_int(st, 6) != 0;
    }
    sqlite3_finalize(st);
    return found;
}

long long store_create_rental(long long member_id, long long tool_id, const char *taken_on,
                              const char *due_on, const char *notes)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes) "
            "VALUES (?1, ?2, ?3, ?4, ?5)", -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(st, 1, member_id);
    sqlite3_bind_int64(st, 2, tool_id);
    sqlite3_bind_text(st, 3, taken_on, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, due_on, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, notes ? notes : "", -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? sqlite3_last_insert_rowid(db) : -1;
}

void store_set_tool_available(long long tool_id, bool available)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "UPDATE tools SET available = ?1 WHERE id = ?2", -1, &st, NULL)
            != SQLITE_OK) {
        return;
    }
    sqlite3_bind_int(st, 1, available ? 1 : 0);
    sqlite3_bind_int64(st, 2, tool_id);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void store_close_rental(long long rental_id)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "UPDATE rentals SET returned = 1 WHERE id = ?1", -1, &st, NULL)
            != SQLITE_OK) {
        return;
    }
    sqlite3_bind_int64(st, 1, rental_id);
    sqlite3_step(st);
    sqlite3_finalize(st);
}
