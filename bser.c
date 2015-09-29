#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "bser.h"
#include "bser_private.h"

bser_t* bser_new_integer(uint64_t value, bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_INT64;
    fill->value.integer = value;
    return fill;
}

bser_t* bser_new_real(double value, bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_REAL;
    fill->value.real = value;
    return fill;
}

bser_t* bser_new_true(bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_TRUE;
    return fill;
}

bser_t* bser_new_false(bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_FALSE;
    return fill;
}

bser_t* bser_new_null(bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_NULL;
    return fill;
}

bser_t* bser_new_string(const char* chars, size_t len, bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_STRING;
    fill->value.string.chars = chars;
    fill->value.string.length = len;
    return fill;
}

bser_t* bser_new_array(
        bser_t* elems, size_t len, bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_ARRAY;
    fill->value.array.elements = elems;
    fill->value.array.length = len;
    return fill;
}

bser_t* bser_new_object(
        bser_key_value_pair_t* fields, size_t length, bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_OBJECT;
    fill->value.object.fields = fields;
    fill->value.object.length = length;
    return fill;
}

static void bser_free_array(bser_t* bser) {
    for (int i = 0; i < bser->value.array.length; ++i) {
        bser_free(&bser->value.array.elements[i]);
    }
}

static void bser_free_object(bser_t* bser) {
    for (int i = 0; i < bser->value.object.length; ++i) {
        bser_free(&bser->value.object.fields[i].value);
    }
}

void bser_free(bser_t* bser) {
    if (bser_is_array(bser)) {
        bser_free_array(bser);
    } else if (bser_is_object(bser)) {
        bser_free_object(bser);
    }
}

char* bser_string_value_new(bser_t* bser) {
    bser_parse_if_necessary(bser);
    return strndup(bser->value.string.chars, bser->value.string.length);
}

int bser_string_strcmp(const char* match, bser_t* bser) {
    bser_parse_if_necessary(bser);
    int cmp = strncmp(match, bser->value.string.chars,
                      bser->value.string.length);
    return cmp == 0 ? match[bser->value.string.length] - '\0' : cmp;
}

bser_t* bser_object_get(bser_t* bser, const char* key) {
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

bser_t* bser_array_get(bser_t* bser, size_t index) {
      bser_parse_if_necessary(bser);
      bser_t* element = &bser->value.array.elements[index];
      if (bser_is_unparsed(element)) {
          /* Can't return an unparsed element unless all element prior
             have been passed. */
          bser_parse_array_elements_to(bser, index);
      }
      return element;
}

bser_t* bser_object_key_at(bser_t* bser, size_t index) {
    bser_parse_if_necessary(bser);
    bser_key_value_pair_t* field = bser_object_pair_at(bser, index);
    if (bser_is_unparsed(&field->key)) {
	    bser_parse_object_fields_to(bser, index);
    }
    return &field->key;
}

bser_t* bser_object_value_at(bser_t* bser, size_t index) {
    bser_parse_if_necessary(bser);
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
