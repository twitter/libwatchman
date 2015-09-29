#ifndef LIBWATCHMAN_BSER_H_
#define LIBWATCHMAN_BSER_H_

#include <stdint.h>
#include <assert.h>

#include <jansson.h>

#include "bser_private.h"

/**
 * BSER is a binary protocol for transferring JSON-like data.  It supports
 * a subset of JSON functionality in a much more compact and easily parsed
 * form.  When watchman receives a request in BSER format, it will respond
 * in kind.  See https://facebook.github.io/watchman/docs/bser.html for
 * description of the protocol.
 */

/* ctors  - if 'fill' is NULL a new object will be allocated and returned,
 * otherwise, fill is initailized and returned */
bser_t* bser_new_integer(int64_t value, bser_t* fill);
bser_t* bser_new_real(double value, bser_t* fill);
bser_t* bser_new_true(bser_t* fill);
bser_t* bser_new_false(bser_t* fill);
bser_t* bser_new_null(bser_t* fill);
bser_t* bser_new_string(const char* chars, size_t len, bser_t* fill);
bser_t* bser_new_array(bser_t* elems, size_t len, bser_t* fill);
bser_t* bser_new_object(bser_key_value_pair_t* fields,
                        size_t length, bser_t* fill);

/* Recursively frees memory allocated under 'bser',
 * without deallocating 'bser' itself. */
void bser_free_contents(bser_t* bser);

/* Frees 'bser' and all memory allocated beneath it. */
void bser_free(bser_t* bser);

/* basic type queries */
int bser_is_integer(bser_t* bser);
int bser_is_real(bser_t* bser);
int bser_is_true(bser_t* bser);
int bser_is_false(bser_t* bser);
int bser_is_boolean(bser_t* bser);
int bser_is_null(bser_t* bser);
int bser_is_string(bser_t* bser);
int bser_is_array(bser_t* bser);
int bser_is_object(bser_t* bser);
/* Parse error resulted in a error node, or node has been freed */
int bser_is_error(bser_t* bser);

/* value retrieval -- assumes type checking has occurred already */
int64_t bser_integer_value(bser_t* bser);

double bser_real_value(bser_t* bser);

const char* bser_string_value(bser_t* bser, size_t* length_ret);
/* Like strcmp(), but matches a bser string with a char* */
int bser_string_strcmp(const char* match, bser_t* bser);

size_t bser_array_size(bser_t* bser);
bser_t* bser_array_get(bser_t* bser, size_t index);

size_t bser_object_size(bser_t* bser);
bser_t* bser_object_get(bser_t* bser, const char* key);
bser_t* bser_object_key_at(bser_t* bser, size_t index);
bser_t* bser_object_value_at(bser_t* bser, size_t index);

/* Retrieve error message if the node is an error node */
const char* bser_error_message(bser_t* bser);

/* Convert a BSER representation into a json (jansson) representation */
json_t* bser2json(bser_t* bser);

#endif /* ndef LIBWATCHMAN_BSER_H */
