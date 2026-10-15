#include "jsonbuf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void buf_reserve(buf_t *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap) {
        return;
    }
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra + 1) {
        cap *= 2;
    }
    char *grown = realloc(b->data, cap);
    if (grown == NULL) {
        abort();
    }
    b->data = grown;
    b->cap = cap;
}

void buf_init(buf_t *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    buf_reserve(b, 0);
    b->data[0] = '\0';
}

void buf_free(buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

void buf_addn(buf_t *b, const char *text, size_t n)
{
    buf_reserve(b, n);
    memcpy(b->data + b->len, text, n);
    b->len += n;
    b->data[b->len] = '\0';
}

void buf_add(buf_t *b, const char *text)
{
    buf_addn(b, text, strlen(text));
}

void buf_addf(buf_t *b, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    va_list probe;
    va_copy(probe, args);
    int needed = vsnprintf(NULL, 0, fmt, probe);
    va_end(probe);
    if (needed > 0) {
        buf_reserve(b, (size_t) needed);
        vsnprintf(b->data + b->len, (size_t) needed + 1, fmt, args);
        b->len += (size_t) needed;
    }
    va_end(args);
}

void buf_add_json_string(buf_t *b, const char *text)
{
    buf_add(b, "\"");
    for (const unsigned char *p = (const unsigned char *) (text ? text : ""); *p; p++) {
        switch (*p) {
        case '"':  buf_add(b, "\\\""); break;
        case '\\': buf_add(b, "\\\\"); break;
        case '\n': buf_add(b, "\\n");  break;
        case '\r': buf_add(b, "\\r");  break;
        case '\t': buf_add(b, "\\t");  break;
        default:
            if (*p < 0x20) {
                buf_addf(b, "\\u%04x", *p);
            } else {
                buf_addn(b, (const char *) p, 1);
            }
        }
    }
    buf_add(b, "\"");
}

void buf_add_html_escaped(buf_t *b, const char *text)
{
    for (const char *p = text ? text : ""; *p; p++) {
        switch (*p) {
        case '&':  buf_add(b, "&amp;");  break;
        case '<':  buf_add(b, "&lt;");   break;
        case '>':  buf_add(b, "&gt;");   break;
        case '"':  buf_add(b, "&quot;"); break;
        case '\'': buf_add(b, "&#39;");  break;
        default:   buf_addn(b, p, 1);
        }
    }
}

static const char *find_field(const char *body, const char *name)
{
    if (body == NULL) {
        return NULL;
    }
    size_t name_len = strlen(name);
    for (const char *p = body; (p = strchr(p, '"')) != NULL; p++) {
        if (strncmp(p + 1, name, name_len) == 0 && p[1 + name_len] == '"') {
            const char *colon = p + 2 + name_len;
            while (*colon == ' ' || *colon == '\t') {
                colon++;
            }
            if (*colon == ':') {
                colon++;
                while (*colon == ' ' || *colon == '\t') {
                    colon++;
                }
                return colon;
            }
        }
    }
    return NULL;
}

char *json_field(const char *body, const char *name)
{
    const char *value = find_field(body, name);
    if (value == NULL || *value != '"') {
        return NULL;
    }
    value++;
    buf_t out;
    buf_init(&out);
    while (*value && *value != '"') {
        if (*value == '\\' && value[1]) {
            value++;
            char decoded = *value;
            switch (decoded) {
            case 'n': decoded = '\n'; break;
            case 'r': decoded = '\r'; break;
            case 't': decoded = '\t'; break;
            default: break;
            }
            buf_addn(&out, &decoded, 1);
        } else {
            buf_addn(&out, value, 1);
        }
        value++;
    }
    return out.data;
}

long json_field_long(const char *body, const char *name, long fallback)
{
    const char *value = find_field(body, name);
    if (value == NULL) {
        return fallback;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    return end == value ? fallback : parsed;
}
