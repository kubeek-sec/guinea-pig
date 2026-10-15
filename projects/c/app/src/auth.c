#define _GNU_SOURCE

#include "auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/hmac.h>

#include "jsonbuf.h"

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void b64url_encode(const unsigned char *in, size_t len, buf_t *out)
{
    for (size_t i = 0; i < len; i += 3) {
        unsigned int block = (unsigned int) in[i] << 16;
        size_t have = 1;
        if (i + 1 < len) {
            block |= (unsigned int) in[i + 1] << 8;
            have = 2;
        }
        if (i + 2 < len) {
            block |= in[i + 2];
            have = 3;
        }
        char chunk[4];
        chunk[0] = B64URL[(block >> 18) & 0x3f];
        chunk[1] = B64URL[(block >> 12) & 0x3f];
        chunk[2] = B64URL[(block >> 6) & 0x3f];
        chunk[3] = B64URL[block & 0x3f];
        buf_addn(out, chunk, have + 1);
    }
}

static int b64url_value(char c)
{
    const char *found = memchr(B64URL, c, sizeof B64URL - 1);
    return found ? (int) (found - B64URL) : -1;
}

static bool b64url_decode(const char *in, size_t len, buf_t *out)
{
    unsigned int block = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        int value = b64url_value(in[i]);
        if (value < 0) {
            return false;
        }
        block = (block << 6) | (unsigned int) value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            char byte = (char) ((block >> bits) & 0xff);
            buf_addn(out, &byte, 1);
        }
    }
    return true;
}

static const char *signing_key(void)
{
    const char *key = getenv("TOOLSHED_TOKEN_KEY");
    return (key && *key) ? key : NULL;
}

static long token_ttl(void)
{
    const char *raw = getenv("TOOLSHED_TOKEN_TTL");
    if (raw == NULL) {
        return 3600;
    }
    long value = strtol(raw, NULL, 10);
    return value > 0 ? value : 3600;
}

static bool sign_part(const char *key, const char *payload, buf_t *out)
{
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (HMAC(EVP_sha256(), key, (int) strlen(key),
             (const unsigned char *) payload, strlen(payload), mac, &mac_len) == NULL) {
        return false;
    }
    b64url_encode(mac, mac_len, out);
    return true;
}

bool auth_issue(const member_t *member, char *out, size_t out_size)
{
    const char *key = signing_key();
    if (key == NULL) {
        return false;
    }
    time_t now = time(NULL);

    buf_t head;
    buf_init(&head);
    b64url_encode((const unsigned char *) "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", 27, &head);

    buf_t claims;
    buf_init(&claims);
    buf_addf(&claims, "{\"sub\":\"%lld\",\"email\":", member->id);
    buf_add_json_string(&claims, member->email);
    buf_add(&claims, ",\"role\":");
    buf_add_json_string(&claims, member->role);
    buf_addf(&claims, ",\"iat\":%lld,\"exp\":%lld}",
             (long long) now, (long long) now + token_ttl());

    buf_t body;
    buf_init(&body);
    buf_add(&body, head.data);
    buf_add(&body, ".");
    b64url_encode((const unsigned char *) claims.data, claims.len, &body);

    buf_t mac;
    buf_init(&mac);
    bool ok = sign_part(key, body.data, &mac);
    if (ok) {
        int written = snprintf(out, out_size, "%s.%s", body.data, mac.data);
        ok = written > 0 && (size_t) written < out_size;
    }

    buf_free(&head);
    buf_free(&claims);
    buf_free(&body);
    buf_free(&mac);
    return ok;
}

bool auth_authenticate(const char *email, const char *password, member_t *out)
{
    if (email == NULL || password == NULL || !store_member_by_email(email, out)) {
        return false;
    }
    return store_check_password(password, out->password);
}

bool auth_from_header(const char *authorization, member_t *out)
{
    if (authorization == NULL || strncmp(authorization, "Bearer ", 7) != 0) {
        return false;
    }
    const char *key = signing_key();
    if (key == NULL) {
        return false;
    }
    const char *token = authorization + 7;
    const char *last_dot = strrchr(token, '.');
    if (last_dot == NULL || last_dot == token) {
        return false;
    }

    size_t body_len = (size_t) (last_dot - token);
    char *body = strndup(token, body_len);
    if (body == NULL) {
        return false;
    }

    buf_t expected;
    buf_init(&expected);
    bool ok = sign_part(key, body, &expected);
    free(body);
    if (!ok) {
        buf_free(&expected);
        return false;
    }

    const char *given = last_dot + 1;
    ok = strlen(given) == expected.len;
    if (ok) {
        unsigned char diff = 0;
        for (size_t i = 0; i < expected.len; i++) {
            diff |= (unsigned char) (given[i] ^ expected.data[i]);
        }
        ok = diff == 0;
    }
    buf_free(&expected);
    if (!ok) {
        return false;
    }

    const char *first_dot = memchr(token, '.', body_len);
    if (first_dot == NULL) {
        return false;
    }
    buf_t claims;
    buf_init(&claims);
    ok = b64url_decode(first_dot + 1, (size_t) (last_dot - first_dot - 1), &claims);
    if (!ok) {
        buf_free(&claims);
        return false;
    }

    long long expiry = json_field_long(claims.data, "exp", 0);
    char *subject = json_field(claims.data, "sub");
    buf_free(&claims);
    if (subject == NULL || expiry <= (long long) time(NULL)) {
        free(subject);
        return false;
    }
    long long id = strtoll(subject, NULL, 10);
    free(subject);
    return store_member(id, out);
}
