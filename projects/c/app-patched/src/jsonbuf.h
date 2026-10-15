/* A growable buffer used to build JSON and HTML responses. */
#ifndef TOOLSHED_JSONBUF_H
#define TOOLSHED_JSONBUF_H

#include <stddef.h>

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_add(buf_t *b, const char *text);
void buf_addn(buf_t *b, const char *text, size_t n);
void buf_addf(buf_t *b, const char *fmt, ...);
void buf_add_json_string(buf_t *b, const char *text);
void buf_add_html_escaped(buf_t *b, const char *text);

/* Reads the value of a top-level string or number field of a flat JSON object.
   Returns a malloc'd copy, or NULL when the field is absent. */
char *json_field(const char *body, const char *name);
long  json_field_long(const char *body, const char *name, long fallback);

#endif
