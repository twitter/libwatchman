#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "bser.h"
#include "bser_private.h"

int bser_is_integer(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_INT64;
}

int bser_is_real(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_REAL;
}

int bser_is_true(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_TRUE;
}

int bser_is_false(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_FALSE;
}

int bser_is_boolean(bser_t* bser)
{
    return bser_is_true(bser) || bser_is_false(bser);
}

int bser_is_null(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_NULL;
}

int bser_is_string(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_STRING;
}

int bser_is_array(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_ARRAY;
}

int bser_is_object(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_OBJECT;
}

int bser_is_error(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    return bser->type == BSER_TAG_ERROR;
}

int64_t bser_integer_value(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    assert(bser_is_integer(bser));
    return bser->value.integer;
}

double bser_real_value(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    assert(bser_is_real(bser));
    return bser->value.real;
}

const char* bser_string_value(bser_t* bser, size_t* length_ret)
{
    bser_parse_if_necessary(bser);
    assert(bser_is_string(bser));
    *length_ret = bser->value.string.length;
    return bser->value.string.chars;
}

size_t bser_array_size(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    assert(bser_is_array(bser));
    return bser->value.array.length;
}

size_t bser_object_size(bser_t* bser)
{
    bser_parse_if_necessary(bser);
    assert(bser_is_object(bser));
    return bser->value.object.length;
}

const char* bser_error_message(bser_t* bser)
{
    assert(bser_is_error(bser));
    return bser->value.error_message;
}

bser_t* bser_new_integer(uint64_t value, bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_INT64;
    fill->value.integer = value;
    return fill;
}

bser_t* bser_new_real(double value, bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_REAL;
    fill->value.real = value;
    return fill;
}

bser_t* bser_new_true(bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_TRUE;
    return fill;
}

bser_t* bser_new_false(bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_FALSE;
    return fill;
}

bser_t* bser_new_null(bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_NULL;
    return fill;
}

bser_t* bser_new_string(const char* chars, size_t len, bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_STRING;
    fill->value.string.chars = chars;
    fill->value.string.length = len;
    return fill;
}

bser_t* bser_new_array(bser_t* elems, size_t len, bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_ARRAY;
    fill->value.array.elements = elems;
    fill->value.array.length = len;
    return fill;
}

bser_t* bser_new_object(bser_key_value_pair_t* fields,
        size_t length, bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_OBJECT;
    fill->value.object.fields = fields;
    fill->value.object.length = length;
    return fill;
}

static void bser_free_array_contents(bser_t* bser)
{
    assert(bser_is_array(bser));
    for (int i = 0; i < bser->value.array.length; ++i) {
        bser_free_contents(&bser->value.array.elements[i]);
    }
    free(bser->value.array.elements);
}

static void bser_free_object_contents(bser_t* bser)
{
    assert(bser_is_object(bser));
    for (int i = 0; i < bser->value.object.length; ++i) {
        bser_free_contents(&bser->value.object.fields[i].value);
    }
    free(bser->value.object.fields);
}

void bser_free_contents(bser_t* bser)
{
    if (bser_is_array(bser)) {
        bser_free_array_contents(bser);
    } else if (bser_is_object(bser)) {
        bser_free_object_contents(bser);
    }
    bser->type = BSER_TAG_ERROR;
    bser->value.error_message = "<deallocated>";
}

void bser_free(bser_t* bser) {
    bser_free_contents(bser);
    free(bser);
}

int bser_string_strcmp(const char* match, bser_t* bser)
{
    assert(bser_is_string(bser));
    bser_parse_if_necessary(bser);
    int cmp = memcmp(match, bser->value.string.chars, bser->value.string.length);
    return cmp == 0 ? (unsigned char)match[bser->value.string.length] : cmp;
}

bser_t* bser_object_get(bser_t* bser, const char* key)
{
    assert(bser_is_object(bser));
    for (int i = 0; i < bser->value.object.length; ++i) {
        bser_key_value_pair_t* pair = bser_object_pair_at(bser, i);
        bser_parse_if_necessary(&pair->key);
        assert(bser_is_string(&pair->key));
        bser_parse_if_necessary(&pair->value);
        if (!bser_string_strcmp(key, &pair->key)) {
            if (bser_is_no_field(&pair->value)) {
                return NULL;
            } else {
                return &pair->value;
            }
        }
    }
    return NULL;
}

bser_t* bser_array_get(bser_t* bser, size_t index)
{
    bser_parse_if_necessary(bser);
    assert(bser_is_array(bser));
    bser_t* element = &bser->value.array.elements[index];

    /* Can't return an unparsed element unless all elements prior
     * have been parsed. */
    bser_parse_array_elements_to(bser, index);
    return element;
}

bser_t* bser_object_key_at(bser_t* bser, size_t index)
{
    bser_parse_if_necessary(bser);
    assert(bser_is_object(bser));
    bser_key_value_pair_t* field = bser_object_pair_at(bser, index);
    if (bser_is_unparsed(&field->key)) {
        bser_parse_object_fields_to(bser, index);
    }
    return &field->key;
}

bser_t* bser_object_value_at(bser_t* bser, size_t index)
{
    bser_parse_if_necessary(bser);
    assert(bser_is_object(bser));
    bser_key_value_pair_t* field = bser_object_pair_at(bser, index);
    if (bser_is_unparsed(&field->value)) {
        bser_parse_object_fields_to(bser, index);
        bser_parse_if_necessary(&field->key);
    }
    if (bser_is_no_field(&field->value)) {
        return NULL;
    } else {
        return &field->value;
    }
}

json_t* bser2json(bser_t* bser)
{
    if (bser_is_integer(bser)) {
        json_int_t v = bser_integer_value(bser);
        return json_integer(v);
    } else if (bser_is_real(bser)) {
        double v = bser_real_value(bser);
        return json_real(v);
    } else if (bser_is_true(bser)) {
        return json_true();
    } else if (bser_is_false(bser)) {
        return json_false();
    } else if (bser_is_null(bser)) {
        return json_null();
    } else if (bser_is_string(bser)) {
        size_t length;
        const char* str = bser_string_value(bser, &length);
        char* dup = strndup(str, length);
        json_t* string = json_string(dup);
        free(dup);
        return string;
    } else if (bser_is_array(bser)) {
        size_t length = bser_array_size(bser);
        json_t* array = json_array();
        for (int i = 0; i < length; ++i) {
            json_array_append_new(array, bser2json(bser_array_get(bser, i)));
        }
        return array;
    } else if (bser_is_object(bser)) {
        size_t length = bser_object_size(bser);
        json_t* object = json_object();
        for (int i = 0; i < length; ++i) {
            size_t key_length;
            bser_t* key = bser_object_key_at(bser, i);
            assert(bser_is_string(key));
            bser_t* value = bser_object_value_at(bser, i);
            if (!bser_is_no_field(value)) {
                const char* key_chars = bser_string_value(key, &key_length);
                assert(key_chars != NULL && *key_chars != '\0');
                char* key_dup = strndup(key_chars, key_length);
                json_object_set_new(object, key_dup, bser2json(value));
                free(key_dup);
            }
        }
        return object;
    } else {
        return NULL;
    }
}
