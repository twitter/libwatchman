#ifndef _LIBWATCHMAN_PROTO_H_
#define _LIBWATCHMAN_PROTO_H_

#include <jansson.h>
#include "bser.h"
#include "bser_parse.h"

/* A wrapper around json (jansson) or bser */

enum { PROTO_BSER, PROTO_JSON };

typedef struct proto_ptr {
    union {
        json_t* json;
        bser_t* bser;
    } u;
    int type;
} proto_t;

proto_t proto_from_json(struct json_t* json) {
    proto_t proto;
    proto.u.json = json;
    proto.type = PROTO_JSON;
    return proto;
}

proto_t proto_from_bser(bser_t* bser) {
    proto_t proto;
    proto.u.bser = bser;
    proto.type = PROTO_BSER;
    return proto;
}

proto_t proto_null() {
    proto_t proto;
    proto.u.json = NULL;
    return proto;
}

int proto_is_null(proto_t p) {
    return p.u.json == NULL;
}

#define PROTO_DISPATCH(ret, name) \
ret proto_##name(proto_t p) { \
    return p.type == PROTO_JSON ? \
        json_##name(p.u.json) : \
        bser_##name(p.u.bser); \
}

PROTO_DISPATCH(int, is_boolean)
PROTO_DISPATCH(int, is_integer)
PROTO_DISPATCH(int, is_real)
PROTO_DISPATCH(int, is_string)
PROTO_DISPATCH(int, is_array)
PROTO_DISPATCH(int, is_object)
PROTO_DISPATCH(int, is_true)
PROTO_DISPATCH(int64_t, integer_value)
PROTO_DISPATCH(double, real_value)
PROTO_DISPATCH(int, array_size)

#undef PROTO_DISPATCH

/* Returns a potentially non-null-terminated read-only string, with a length */
const char* proto_string_value(proto_t p, size_t* length) {
    if (p.type == PROTO_JSON) {
        const char* v = json_string_value(p.u.json);
        *length = strlen(v);
        return v;
    } else {
        return bser_string_value(p.u.bser, length);
    }
}

/* Returns a dynamically-allocated null-terminated c-string (caller-owned) */
char* proto_strdup(proto_t p) {
    size_t length;
    const char* v = proto_string_value(p, &length);
    if (v[length] == '\0') {
        return strdup(v);
    } else {
        char* res = malloc(length + 1);
        memcpy(res, v, length);
        res[length] = '\0';
        return res;
    }
}

proto_t proto_array_get(proto_t p, int index) {
    return p.type == PROTO_JSON ?
        proto_from_json(json_array_get(p.u.json, index)) :
        proto_from_bser(bser_array_get(p.u.bser, index));
}

proto_t proto_object_get(proto_t p, const char* key) {
    return p.type == PROTO_JSON ?
        proto_from_json(json_object_get(p.u.json, key)) :
        proto_from_bser(bser_object_get(p.u.bser, key));
}

char* proto_dumps(proto_t p, int flags) {
    json_t* json = p.u.json;
    char* result;
    if (p.type == PROTO_BSER) {
        json = bser2json(p.u.bser);
    }
    result = json_dumps(json, flags);
    if (p.type == PROTO_BSER) {
        json_decref(json);
    }
    return result;
}

void proto_decref(proto_t p) {
    if (p.type == PROTO_JSON) {
        json_decref(p.u.json);
    }
}

#endif /* ndef _LIBWATCHMAN_PROTO_H_ */
