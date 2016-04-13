
#include "bser.h"

#include <stdio.h>
#include <string.h>
#include <jansson.h>

static bser_t* bser_new_unparsed(
        bser_buffer_t* buffer, bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_UNPARSED;
    fill->value.unparsed.buffer = buffer;
    return fill;
}

static bser_t* bser_new_error(
        const char* message, bser_t* fill) {
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_ERROR;
    fill->value.error_message = message;
    return fill;
}

static bser_t* bser_new_compact_object(
        bser_buffer_t* buffer, bser_t* header, bser_t* fill) {
    size_t sz = bser_array_size(header);
    bser_key_value_pair_t* fields = (bser_key_value_pair_t*)malloc(
        sizeof(bser_key_value_pair_t) * sz);

    for (int i = 0; i < sz; ++i) {
        fields[i].key = *(bser_array_get(header, i));
        bser_new_unparsed(buffer, &fields[i].value);
    }
    bser_new_object(fields, sz, fill);
    return fill;
}

bser_t* bser_parse(uint8_t* data, size_t buflen, bser_t* fill) {
    if (fill == NULL) {
        fill = (bser_t*)malloc(sizeof(bser_t));
    }
    bser_buffer_t* buffer = (bser_buffer_t*)malloc(sizeof(*buffer));
    buffer->data = data;
    buffer->datalen = buflen;
    buffer->cursor = 0;

    bser_new_unparsed(buffer, fill);
    return fill;
}

static int integer_from_file(FILE* fp, uint64_t* value) {
    uint8_t  v8  = 0;
    uint16_t v16 = 0;
    uint32_t v32 = 0;
    uint64_t v64 = 0;

    switch (fgetc(fp)) {
        case BSER_TAG_INT8:
            if (fread(&v8, sizeof(v8), 1, fp) == 1) {
                *value = v8;
                return 0;
            }
        case BSER_TAG_INT16:
            if (fread(&v16, sizeof(v16), 1, fp) == 1) {
                *value = v16;
                return 0;
            }
        case BSER_TAG_INT32:
            if (fread(&v32, sizeof(v32), 1, fp) == 1) {
                *value = v32;
                return 0;
            }
        case BSER_TAG_INT64:
            if (fread(&v64, sizeof(v64), 1, fp) == 1) {
                *value = v64;
                return 0;
            }
    }
    return -1;
}

bser_t* bser_parse_from_file(FILE* fp, bser_t* fill) {
    uint8_t* buf;
    char magic[2];
    uint64_t size;

    if (fread(magic, 1, 2, fp) != 2 ||
        magic[0] != '\0' ||
        magic[1] != '\1') {
        bser_new_error("Could not read bser magic values", fill);
    } else if (integer_from_file(fp, &size)) {
        bser_new_error("Could not read bser length", fill);
    } else {
        buf = (uint8_t*)malloc(size);
        if (fread(buf, 1, size, fp) != size) {
            bser_new_error("Could not read full bser data", fill);
        } else {
            return bser_parse(buf, size, fill);
        }
    }
    return fill;
}

void bser_parse_array(bser_t* fill, bser_buffer_t* buffer) {
     bser_t length;
     bser_new_unparsed(buffer, &length);
     if (bser_is_integer(&length)) {
        size_t sz = (size_t)bser_integer_value(&length);
        bser_t* array = (bser_t*)malloc(sizeof(bser_t) * sz);
        for (int i = 0; i < sz; ++i) {
            bser_new_unparsed(buffer, &array[i]);
        }
        bser_new_array(array, sz, fill);
     } else {
        bser_new_error("Array does not have an integer length", fill);
     }
}

void bser_parse_object(bser_t* fill, bser_buffer_t* buffer) {
     bser_t length;
     bser_new_unparsed(buffer, &length);
     if (bser_is_integer(&length)) {
        size_t sz = (size_t)bser_integer_value(&length);
        bser_key_value_pair_t* array = (bser_key_value_pair_t*)malloc(
            sizeof(bser_key_value_pair_t) * sz);
        for (int i = 0; i < sz; ++i) {
            bser_new_unparsed(buffer, &array[i].key);
            bser_new_unparsed(buffer, &array[i].value);
        }
        bser_new_object(array, sz, fill);
     } else {
        bser_new_error("Object does not have an integer length", fill);
     }
}

void bser_parse_string(bser_t* fill, bser_buffer_t* buffer) {
     bser_t length;
     bser_new_unparsed(buffer, &length);
     if (bser_is_integer(&length)) {
        size_t sz = (size_t)bser_integer_value(&length);
        const char* chars = (const char*)&buffer->data[buffer->cursor];
        buffer->cursor += sz;
        bser_new_string(chars, sz, fill);
     } else {
        bser_new_error("String does not have an integer length", fill);
     }
}

void bser_parse_compact_array(bser_t* fill, bser_buffer_t* buffer) {
    bser_t header;
    bser_new_unparsed(buffer, &header);
    if (bser_is_array(&header)) {
        size_t header_length = bser_array_size(&header);
        for (int i = 0; i < header_length; ++i) {
            bser_parse_if_necessary(bser_array_get(&header, i));
        }
        bser_t length;
        bser_new_unparsed(buffer, &length);
        if (bser_is_integer(&length)) {
            size_t sz = (size_t)bser_integer_value(&length);
            bser_t* array = (bser_t*)malloc(sizeof(bser_t) * sz);
            bser_new_array(array, sz, fill);
            for (int i = 0; i < sz; ++i) {
                bser_new_compact_object(buffer, &header, &array[i]);
            }
        } else {
            bser_new_error("Compact array does not have an integer length", fill);
        }
    } else {
        bser_new_error("Compact array does not have a header array", fill);
    }
}

void bser_parse_generic(bser_t* fill, bser_buffer_t* buffer) {
    if (buffer->cursor > buffer->datalen) {
        fill->type = BSER_TAG_ERROR;
        fill->value.error_message = "out of data";
    } else {
        uint8_t tag = buffer->data[buffer->cursor++];
        uint8_t* data = &buffer->data[buffer->cursor];

        switch (tag) {
            case BSER_TAG_ARRAY:
                bser_parse_array(fill, buffer);
                break;
            case BSER_TAG_OBJECT:
                bser_parse_object(fill, buffer);
                break;
            case BSER_TAG_STRING:
                bser_parse_string(fill, buffer);
                break;
            case BSER_TAG_INT8:
                bser_new_integer(*(int8_t*)data, fill);
                buffer->cursor += sizeof(int8_t);
                break;
            case BSER_TAG_INT16:
                bser_new_integer(*(int16_t*)data, fill);
                buffer->cursor += sizeof(int16_t);
                break;
            case BSER_TAG_INT32:
                bser_new_integer(*(int32_t*)data, fill);
                buffer->cursor += sizeof(int32_t);
                break;
            case BSER_TAG_INT64:
                bser_new_integer(*(int64_t*)data, fill);
                buffer->cursor += sizeof(int64_t);
                break;
            case BSER_TAG_REAL:
                bser_new_real(*(double*)data, fill);
                buffer->cursor += sizeof(double);
                break;
            case BSER_TAG_TRUE:
                bser_new_true(fill);
                break;
            case BSER_TAG_FALSE:
                bser_new_false(fill);
                break;
            case BSER_TAG_NULL:
                bser_new_null(fill);
                break;
            case BSER_TAG_COMPACT_ARRAY:
                bser_parse_compact_array(fill, buffer);
                break;
            case BSER_TAG_NO_FIELD:
                fill->type = BSER_TAG_NO_FIELD;
                break;
            default:
                bser_new_error("unknown tag in data stream", fill);
                break;
        }
    }
}

void bser_parse_array_elements_to(bser_t* array, size_t limit) {
    /* Search back to find first parsed, and parse all from there */
    size_t index = limit - 1;
    while (bser_is_unparsed(&array->value.array.elements[index]) &&
           index > 0) {
        --index;
    }
    for (int i = index; i < limit; ++i) {
        bser_parse_if_necessary(&array->value.array.elements[i]);
    }
}

void bser_parse_object_fields_to(bser_t* obj, size_t limit) {
    /* Search back to find first parsed, and parse all from there */
    size_t index = limit - 1;
    while (bser_is_unparsed(&obj->value.object.fields[index].value) &&
           index > 0) {
        --index;
    }

    for (int i = index; i < limit; ++i) {
        bser_key_value_pair_t* pair = bser_object_pair_at(obj, i);
        bser_parse_if_necessary(&pair->key);
        bser_parse_if_necessary(&pair->value);
    }
}

json_t* bser2json(bser_t* bser) {
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
            json_array_append_new(array,
                bser2json(bser_array_get(bser, i)));
        }
        return array;
    } else if (bser_is_object(bser)) {
        size_t length = bser_object_length(bser);
        json_t* object = json_object();
        for (int i = 0; i < length; ++i) {
            size_t key_length;
            bser_t* key = bser_object_key_at(bser, i);
            const char* key_chars = bser_string_value(key, &key_length);
            char* key_dup = strndup(key_chars, key_length);
            bser_t* value = bser_object_value_at(bser, i);
            if (!bser_is_no_field(value)) {
                json_object_set_new(object, key_dup, bser2json(value));
            }
            free(key_dup);
        }
        return object;
    } else {
        return NULL;
    }
}
