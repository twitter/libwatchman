#ifndef _LIBWATCHMAN_BSER_H_
#define _LIBWATCHMAN_BSER_H_

#include <stdint.h>

#include "bser_private.h"

/* ctors  - if 'fill' is NULL a new object will be allocated and returned,
   otherwise, fill is initailized and returned */
bser_t* bser_new_integer(uint64_t value, bser_t* fill);
bser_t* bser_new_real(double value, bser_t* fill);
bser_t* bser_new_true(bser_t* fill);
bser_t* bser_new_false(bser_t* fill);
bser_t* bser_new_null(bser_t* fill);
bser_t* bser_new_string(const char* chars, size_t len, bser_t* fill);
bser_t* bser_new_array(bser_t* elems, size_t len,
    bser_t* fill);
bser_t* bser_new_object(bser_key_value_pair_t* fields, size_t length, bser_t* fill);

void bser_free(bser_t* bser);

/* type queries */
static inline int bser_is_integer(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_INT64;
}
static inline int bser_is_real(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_REAL;
}
static inline int bser_is_true(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_TRUE;
}
static inline int bser_is_false(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_FALSE;
}
static inline int bser_is_boolean(bser_t* bser) {
    return bser_is_true(bser) || bser_is_false(bser);
}
static inline int bser_is_null(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_NULL;
}
static inline int bser_is_string(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_STRING;
}
static inline int bser_is_array(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_ARRAY;
}
static inline int bser_is_object(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_OBJECT;
}
/* Parse error resulted in a error node */
static inline int bser_is_error(bser_t* bser) {
    return bser->type == BSER_TAG_ERROR;
}

/* value retrieval -- assumes type checking has occurred already */
static inline int64_t bser_integer_value(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->value.integer;
}

static inline double bser_real_value(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->value.real;
}

static inline const char* bser_string_value(bser_t* bser, size_t* length_ret) {
    bser_parse_if_necessary(bser);
    *length_ret = bser->value.string.length;
    return bser->value.string.chars;
}

/* Like strcmp(), but matches a bser string with a char* */
int bser_string_strcmp(const char* match, bser_t* bser);

static inline size_t bser_array_size(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->value.array.length;
}

bser_t* bser_array_get(bser_t* bser, size_t index);

static inline size_t bser_object_length(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return bser->value.object.length;
}

bser_t* bser_object_key_at(bser_t* bser, size_t index);
bser_t* bser_object_value_at(bser_t* bser, size_t index);

static inline const char* bser_error_message(bser_t* bser) {
    return bser->value.error_message;
}

bser_t* bser_object_get(bser_t* bser, const char* key);

#endif /* ndef _LIBWATCHMAN_BSER_H */
