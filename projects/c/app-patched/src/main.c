/* Toolshed — the lending service of a neighbourhood workshop. */
#define _GNU_SOURCE

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <microhttpd.h>
#include <openssl/rand.h>

#include "auth.h"
#include "jsonbuf.h"
#include "store.h"

#define VERSION          "1.4.2"
#define DEFAULT_DAYS     7
#define MAX_BODY_BYTES   (1024 * 1024)
#define MAX_PHOTO_BYTES  (8 * 1024 * 1024)

static const char *SORTABLE[] = {"name", "category", "daily_rate", NULL};

static const struct {
    const char *ext;
    const char *type;
} PHOTO_TYPES[] = {
    {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"},
    {"png", "image/png"},  {"webp", "image/webp"},
    {NULL, NULL},
};

static char upload_dir[512];

/* Accumulates an upload across the several calls libmicrohttpd makes per request. */
typedef struct {
    buf_t                 body;
    struct MHD_PostProcessor *post;
    buf_t                 photo;
    char                  filename[256];
    bool                  too_large;
} request_t;

static const char *photo_type_for(const char *ext)
{
    for (int i = 0; PHOTO_TYPES[i].ext; i++) {
        if (strcasecmp(PHOTO_TYPES[i].ext, ext) == 0) {
            return PHOTO_TYPES[i].type;
        }
    }
    return NULL;
}

static enum MHD_Result respond(struct MHD_Connection *connection, unsigned int status,
                               const char *type, const char *body, size_t len,
                               const char *extra_header, const char *extra_value)
{
    struct MHD_Response *response =
        MHD_create_response_from_buffer(len, (void *) body, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, type);
    if (extra_header) {
        MHD_add_response_header(response, extra_header, extra_value);
    }
    enum MHD_Result rc = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return rc;
}

static enum MHD_Result send_json(struct MHD_Connection *connection, unsigned int status,
                                 const char *body)
{
    return respond(connection, status, "application/json", body, strlen(body), NULL, NULL);
}

static enum MHD_Result send_error(struct MHD_Connection *connection, unsigned int status,
                                  const char *message)
{
    buf_t out;
    buf_init(&out);
    buf_add(&out, "{\"error\":");
    buf_add_json_string(&out, message);
    buf_add(&out, "}");
    enum MHD_Result rc = send_json(connection, status, out.data);
    buf_free(&out);
    return rc;
}

static bool signed_in(struct MHD_Connection *connection, member_t *member)
{
    const char *header =
        MHD_lookup_connection_value(connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_AUTHORIZATION);
    return auth_from_header(header, member);
}

static void member_to_json(const member_t *member, buf_t *out)
{
    buf_addf(out, "{\"id\":%lld,\"email\":", member->id);
    buf_add_json_string(out, member->email);
    buf_add(out, ",\"full_name\":");
    buf_add_json_string(out, member->full_name);
    buf_add(out, ",\"role\":");
    buf_add_json_string(out, member->role);
    buf_add(out, "}");
}

static void iso_date(time_t when, char *out, size_t size)
{
    struct tm parts;
    gmtime_r(&when, &parts);
    strftime(out, size, "%Y-%m-%d", &parts);
}

/* ------------------------------------------------------------------ routes */

static enum MHD_Result route_home(struct MHD_Connection *connection)
{
    buf_t tools;
    buf_init(&tools);
    store_top_tools(20, &tools);

    buf_t page;
    buf_init(&page);
    buf_add(&page,
        "<!doctype html>\n<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\"><title>Toolshed</title>\n"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}\n"
        "table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;"
        "padding:.5rem;text-align:left}\n.out{color:#999}</style></head>\n"
        "<body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>\n"
        "<table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>\n");

    /* Re-read the rows one by one so each cell can be escaped on its way out. */
    for (int id = 1;; id++) {
        tool_t tool;
        if (!store_tool(id, &tool)) {
            if (id > 64) {
                break;
            }
            continue;
        }
        buf_add(&page, "<tr><td>");
        buf_add_html_escaped(&page, tool.name);
        buf_add(&page, "</td><td>");
        buf_add_html_escaped(&page, tool.category);
        buf_addf(&page, "</td><td>%.2f &euro;</td><td>%s</td></tr>\n", tool.daily_rate,
                 tool.available ? "on the rack" : "<span class=\"out\">out</span>");
        if (id > 64) {
            break;
        }
    }
    buf_add(&page,
        "</table><p><a href=\"/openapi.yml\">API description</a></p></body></html>\n");

    enum MHD_Result rc =
        respond(connection, MHD_HTTP_OK, "text/html", page.data, page.len, NULL, NULL);
    buf_free(&tools);
    buf_free(&page);
    return rc;
}

static enum MHD_Result route_openapi(struct MHD_Connection *connection)
{
    FILE *file = fopen("openapi.yml", "rb");
    if (file == NULL) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no API description here");
    }
    buf_t out;
    buf_init(&out);
    char chunk[4096];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, file)) > 0) {
        buf_addn(&out, chunk, got);
    }
    fclose(file);
    enum MHD_Result rc =
        respond(connection, MHD_HTTP_OK, "application/yaml", out.data, out.len, NULL, NULL);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_list_tools(struct MHD_Connection *connection)
{
    const char *sort = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "sort");
    if (sort == NULL) {
        sort = "name";
    }
    bool allowed = false;
    for (int i = 0; SORTABLE[i]; i++) {
        if (strcmp(SORTABLE[i], sort) == 0) {
            allowed = true;
            break;
        }
    }
    if (!allowed) {
        char message[128];
        snprintf(message, sizeof message, "cannot sort on '%s'", sort);
        return send_error(connection, MHD_HTTP_BAD_REQUEST, message);
    }
    buf_t out;
    buf_init(&out);
    buf_add(&out, "{\"tools\":");
    store_tools_ordered_by(sort, &out);
    buf_add(&out, "}");
    enum MHD_Result rc = send_json(connection, MHD_HTTP_OK, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_search_tools(struct MHD_Connection *connection)
{
    const char *term = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "q");
    buf_t out;
    buf_init(&out);
    buf_add(&out, "{\"query\":");
    buf_add_json_string(&out, term ? term : "");
    buf_add(&out, ",\"tools\":");
    store_search_tools(term ? term : "", &out);
    buf_add(&out, "}");
    enum MHD_Result rc = send_json(connection, MHD_HTTP_OK, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_get_tool(struct MHD_Connection *connection, long long id)
{
    tool_t tool;
    if (!store_tool(id, &tool)) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such tool");
    }
    buf_t out;
    buf_init(&out);
    tool_to_json(&tool, &out);
    enum MHD_Result rc = send_json(connection, MHD_HTTP_OK, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_sign_in(struct MHD_Connection *connection, const char *body)
{
    char *email = json_field(body, "email");
    char *password = json_field(body, "password");
    member_t member;
    bool ok = auth_authenticate(email ? email : "", password ? password : "", &member);
    free(email);
    free(password);
    if (!ok) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "bad credentials");
    }
    char token[TOOLSHED_TOKEN_MAX];
    if (!auth_issue(&member, token, sizeof token)) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot issue a token");
    }
    buf_t out;
    buf_init(&out);
    buf_add(&out, "{\"token\":");
    buf_add_json_string(&out, token);
    buf_add(&out, ",\"role\":");
    buf_add_json_string(&out, member.role);
    buf_add(&out, "}");
    enum MHD_Result rc = send_json(connection, MHD_HTTP_OK, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_whoami(struct MHD_Connection *connection)
{
    member_t member;
    if (!signed_in(connection, &member)) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    buf_t out;
    buf_init(&out);
    member_to_json(&member, &out);
    enum MHD_Result rc = send_json(connection, MHD_HTTP_OK, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_get_member(struct MHD_Connection *connection, long long id)
{
    member_t caller;
    if (!signed_in(connection, &caller)) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    if (strcmp(caller.role, "staff") != 0) {
        return send_error(connection, MHD_HTTP_FORBIDDEN, "staff only");
    }
    member_t member;
    if (!store_member(id, &member)) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such member");
    }
    buf_t out;
    buf_init(&out);
    member_to_json(&member, &out);
    enum MHD_Result rc = send_json(connection, MHD_HTTP_OK, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_my_rentals(struct MHD_Connection *connection)
{
    member_t member;
    if (!signed_in(connection, &member)) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    buf_t out;
    buf_init(&out);
    buf_add(&out, "{\"rentals\":");
    store_rentals_of(member.id, &out);
    buf_add(&out, "}");
    enum MHD_Result rc = send_json(connection, MHD_HTTP_OK, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_take_out(struct MHD_Connection *connection, const char *body)
{
    member_t member;
    if (!signed_in(connection, &member)) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    long long tool_id = json_field_long(body, "tool_id", -1);
    tool_t tool;
    if (!store_tool(tool_id, &tool)) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such tool");
    }
    if (!tool.available) {
        return send_error(connection, MHD_HTTP_CONFLICT, "already out");
    }
    long days = json_field_long(body, "days", DEFAULT_DAYS);
    if (days <= 0) {
        days = DEFAULT_DAYS;
    }
    char *notes = json_field(body, "notes");
    time_t now = time(NULL);
    char taken_on[TOOLSHED_DATE_MAX];
    char due_on[TOOLSHED_DATE_MAX];
    iso_date(now, taken_on, sizeof taken_on);
    iso_date(now + days * 86400, due_on, sizeof due_on);

    long long id = store_create_rental(member.id, tool.id, taken_on, due_on, notes ? notes : "");
    free(notes);
    if (id < 0) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot record the rental");
    }
    store_set_tool_available(tool.id, false);

    buf_t out;
    buf_init(&out);
    buf_addf(&out, "{\"id\":%lld,\"due_on\":", id);
    buf_add_json_string(&out, due_on);
    buf_add(&out, "}");
    enum MHD_Result rc = send_json(connection, MHD_HTTP_CREATED, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_bring_back(struct MHD_Connection *connection, long long rental_id)
{
    member_t member;
    if (!signed_in(connection, &member)) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    rental_t rental;
    if (!store_rental_of(rental_id, member.id, &rental)) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such rental");
    }
    store_close_rental(rental.id);
    store_set_tool_available(rental.tool_id, true);
    return send_json(connection, MHD_HTTP_OK, "{\"status\":\"returned\"}");
}

static enum MHD_Result route_upload_photo(struct MHD_Connection *connection, request_t *state)
{
    member_t member;
    if (!signed_in(connection, &member)) {
        return send_error(connection, MHD_HTTP_UNAUTHORIZED, "authentication required");
    }
    if (state->too_large) {
        return send_error(connection, MHD_HTTP_BAD_REQUEST, "photo too large");
    }
    if (state->photo.len == 0 || state->filename[0] == '\0') {
        return send_error(connection, MHD_HTTP_BAD_REQUEST, "no photo");
    }
    const char *dot = strrchr(state->filename, '.');
    const char *type = dot ? photo_type_for(dot + 1) : NULL;
    if (type == NULL) {
        char message[128];
        snprintf(message, sizeof message, "%s not accepted", dot ? dot : "file");
        return send_error(connection, MHD_HTTP_BAD_REQUEST, message);
    }

    unsigned char token[16];
    if (RAND_bytes(token, sizeof token) != 1) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot name the photo");
    }
    char name[64];
    for (size_t i = 0; i < sizeof token; i++) {
        snprintf(name + i * 2, 3, "%02x", token[i]);
    }
    snprintf(name + sizeof token * 2, sizeof name - sizeof token * 2, "%s", dot);

    char path[768];
    snprintf(path, sizeof path, "%s/%s", upload_dir, name);
    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        return send_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "cannot store the photo");
    }
    fwrite(state->photo.data, 1, state->photo.len, file);
    fclose(file);

    buf_t out;
    buf_init(&out);
    buf_add(&out, "{\"name\":");
    buf_add_json_string(&out, name);
    buf_add(&out, ",\"owner\":");
    buf_add_json_string(&out, member.email);
    buf_add(&out, "}");
    enum MHD_Result rc = send_json(connection, MHD_HTTP_CREATED, out.data);
    buf_free(&out);
    return rc;
}

static enum MHD_Result route_fetch_photo(struct MHD_Connection *connection, const char *raw_name)
{
    const char *slash = strrchr(raw_name, '/');
    const char *name = slash ? slash + 1 : raw_name;
    const char *dot = strrchr(name, '.');
    const char *type = dot ? photo_type_for(dot + 1) : NULL;
    if (type == NULL || strstr(name, "..") != NULL) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such photo");
    }

    char path[768];
    snprintf(path, sizeof path, "%s/%s", upload_dir, name);
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return send_error(connection, MHD_HTTP_NOT_FOUND, "no such photo");
    }
    buf_t out;
    buf_init(&out);
    char chunk[4096];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, file)) > 0) {
        buf_addn(&out, chunk, got);
    }
    fclose(file);
    enum MHD_Result rc = respond(connection, MHD_HTTP_OK, type, out.data, out.len,
                                 "X-Content-Type-Options", "nosniff");
    buf_free(&out);
    return rc;
}

/* ----------------------------------------------------------------- plumbing */

static enum MHD_Result collect_photo(void *cls, enum MHD_ValueKind kind, const char *key,
                                     const char *filename, const char *content_type,
                                     const char *transfer_encoding, const char *data,
                                     uint64_t off, size_t size)
{
    (void) kind; (void) content_type; (void) transfer_encoding; (void) off;
    request_t *state = cls;
    if (strcmp(key, "photo") != 0) {
        return MHD_YES;
    }
    if (filename && state->filename[0] == '\0') {
        snprintf(state->filename, sizeof state->filename, "%s", filename);
    }
    if (state->photo.len + size > MAX_PHOTO_BYTES) {
        state->too_large = true;
        return MHD_YES;
    }
    buf_addn(&state->photo, data, size);
    return MHD_YES;
}

/* Matches "/api/tools/42" and friends; returns the trailing id, or -1. */
static long long tail_id(const char *url, const char *prefix)
{
    size_t len = strlen(prefix);
    if (strncmp(url, prefix, len) != 0 || url[len] == '\0') {
        return -1;
    }
    char *end = NULL;
    long long id = strtoll(url + len, &end, 10);
    return (end && *end == '\0') ? id : -1;
}

static enum MHD_Result handle(void *cls, struct MHD_Connection *connection, const char *url,
                              const char *method, const char *version, const char *upload_data,
                              size_t *upload_data_size, void **con_cls)
{
    (void) cls; (void) version;

    if (*con_cls == NULL) {
        request_t *state = calloc(1, sizeof *state);
        if (state == NULL) {
            return MHD_NO;
        }
        buf_init(&state->body);
        buf_init(&state->photo);
        if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
            state->post = MHD_create_post_processor(connection, 64 * 1024, collect_photo, state);
        }
        *con_cls = state;
        return MHD_YES;
    }

    request_t *state = *con_cls;

    if (*upload_data_size != 0) {
        if (state->post) {
            MHD_post_process(state->post, upload_data, *upload_data_size);
        }
        if (state->body.len + *upload_data_size <= MAX_BODY_BYTES) {
            buf_addn(&state->body, upload_data, *upload_data_size);
        }
        *upload_data_size = 0;
        return MHD_YES;
    }

    bool is_get = strcmp(method, MHD_HTTP_METHOD_GET) == 0;
    bool is_post = strcmp(method, MHD_HTTP_METHOD_POST) == 0;

    if (is_get && strcmp(url, "/healthz") == 0) {
        return send_json(connection, MHD_HTTP_OK,
                         "{\"status\":\"ok\",\"version\":\"" VERSION "\"}");
    }
    if (is_get && strcmp(url, "/openapi.yml") == 0) {
        return route_openapi(connection);
    }
    if (is_get && strcmp(url, "/") == 0) {
        return route_home(connection);
    }
    if (is_get && strcmp(url, "/api/tools") == 0) {
        return route_list_tools(connection);
    }
    if (is_get && strcmp(url, "/api/tools/search") == 0) {
        return route_search_tools(connection);
    }
    if (is_get) {
        long long id = tail_id(url, "/api/tools/");
        if (id >= 0) {
            return route_get_tool(connection, id);
        }
    }
    if (is_post && strcmp(url, "/api/session") == 0) {
        return route_sign_in(connection, state->body.data);
    }
    if (is_get && strcmp(url, "/api/members/me") == 0) {
        return route_whoami(connection);
    }
    if (is_get) {
        long long id = tail_id(url, "/api/members/");
        if (id >= 0) {
            return route_get_member(connection, id);
        }
    }
    if (is_get && strcmp(url, "/api/rentals") == 0) {
        return route_my_rentals(connection);
    }
    if (is_post && strcmp(url, "/api/rentals") == 0) {
        return route_take_out(connection, state->body.data);
    }
    if (is_post && strncmp(url, "/api/rentals/", 13) == 0) {
        const char *suffix = strstr(url, "/return");
        if (suffix && suffix[7] == '\0') {
            long long id = strtoll(url + 13, NULL, 10);
            return route_bring_back(connection, id);
        }
    }
    if (is_post && strcmp(url, "/api/photos") == 0) {
        return route_upload_photo(connection, state);
    }
    if (is_get && strncmp(url, "/api/photos/", 12) == 0) {
        return route_fetch_photo(connection, url + 12);
    }
    return send_error(connection, MHD_HTTP_NOT_FOUND, "no such route");
}

static void request_completed(void *cls, struct MHD_Connection *connection, void **con_cls,
                              enum MHD_RequestTerminationCode code)
{
    (void) cls; (void) connection; (void) code;
    request_t *state = *con_cls;
    if (state == NULL) {
        return;
    }
    if (state->post) {
        MHD_destroy_post_processor(state->post);
    }
    buf_free(&state->body);
    buf_free(&state->photo);
    free(state);
    *con_cls = NULL;
}

static const char *env_or(const char *key, const char *fallback)
{
    const char *value = getenv(key);
    return (value && *value) ? value : fallback;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    const char *db_file = env_or("TOOLSHED_DB", "var/toolshed.db");
    snprintf(upload_dir, sizeof upload_dir, "%s", env_or("TOOLSHED_UPLOADS", "var/uploads"));
    mkdir("var", 0750);
    mkdir(upload_dir, 0750);

    if (store_open(db_file) != 0) {
        fprintf(stderr, "cannot open the database at %s\n", db_file);
        return 1;
    }

    unsigned short port = (unsigned short) strtol(env_or("PORT", "8000"), NULL, 10);
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, port, NULL, NULL,
        &handle, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, &request_completed, NULL,
        MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 30,
        MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "cannot listen on port %u\n", port);
        store_close();
        return 1;
    }

    printf("toolshed %s listening on :%u\n", VERSION, port);
    fflush(stdout);
    for (;;) {
        pause();
    }
}
