#include <stdio.h>
#include <string.h>

#include "bser.h"

/**
 * BSER parsing is done lazily, and does not copy strings out of the buffer.
 * This is accomplished by initializing each new object that we encounter
 * as an "unparsed" object, which contains only a pointer to the data buffer
 * (which itself has a cursor).  The first time an object is queried or a
 * value is requested of it, it accesses the buffer and reads only the data
 * it needs to satisfy the request.  For unit types, this usually means reading
 * the tag and all the data.  For strings, the length is read and a pointer
 * to the string data in the buffer is stored in the object.
 *
 * Parsing occurs in the order that the data appears in the buffer.  That is,
 * if an object's data appears earlier in the buffer than a different object,
 * then the first object is guaranteed to be parsed first.  The buffer is a
 * stream and cannot be randomly accessed.  The in-order parsing happens in
 * the implementation of the 'array' and 'object' types, which are the only
 * composite types in the system.  When these are initially parsed, the read
 * only the header information (including the size) and allocate an array to
 * use for storage and this storage is initialized to all unparsed object.
 * However, when an element or a field is accessed, the query methods ensures
 * that all elements or fields before the requested field are fully-parsed
 * (from first to last).
 */

static bser_t*
new_unparsed(bser_buffer_t* buffer, bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_UNPARSED;
    fill->value.unparsed = buffer;
    return fill;
}

static bser_t*
new_error(const char* message, bser_t* fill)
{
    if (fill == NULL) {
        fill = bser_alloc();
    }
    fill->type = BSER_TAG_ERROR;
    fill->value.error_message = message;
    return fill;
}

static void
new_compact_object(bser_buffer_t* buffer, bser_t* header, bser_t* fill)
{
    assert(bser_is_array(header));
    size_t sz = bser_array_size(header);
    bser_key_value_pair_t* fields = malloc(sizeof(*fields) * sz);
    if (fields == NULL) {
        new_error("Could not allocate enough memory to hold "
                  "compact object fields", fill);
    } else {
        for (int i = 0; i < sz; ++i) {
            fields[i].key = *(bser_array_get(header, i));
            new_unparsed(buffer, &fields[i].value);
        }
        bser_new_object(fields, sz, fill);
    }
}

static bser_buffer_t*
new_read_buffer(void* data, size_t buflen, int offset)
{
    bser_buffer_t* buffer = malloc(sizeof(*buffer));
    buffer->data = data;
    buffer->datalen = buflen;
    buffer->cursor = offset;
    return buffer;
}

bser_t*
bser_parse_content(void* data, size_t buflen, bser_t* fill)
{
    bser_buffer_t* read_buffer = new_read_buffer(data, buflen, 0);
    /* Create lazily-parsed node that will self-parse when it is accessed */
    return new_unparsed(read_buffer, fill);
}

static int
integer_from_file(FILE* fp, int64_t* value)
{
    int8_t  v8  = 0;
    int16_t v16 = 0;
    int32_t v32 = 0;
    int64_t v64 = 0;

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

bser_t*
bser_parse_buffer(void* buffer, size_t buflen, bser_t* fill)
{
    uint8_t* magic = buffer;
    if (buflen < 2 || magic[0] != 0 || magic[1] != 1) {
        return new_error("Could not read bser magic values", fill);
    } else {
        bser_t length;
        bser_buffer_t* read_buffer = new_read_buffer(buffer, buflen, 2);
        new_unparsed(read_buffer, &length);
        if (!bser_is_integer(&length)) {
            return new_error("Could not read bser length", fill);
        } else {
            size_t sz = bser_integer_value(&length);
            if (read_buffer->cursor + sz > buflen) {
                return new_error("Truncated buffer", fill);
            } else {
                return new_unparsed(read_buffer, fill);
            }
        }
    }
}

bser_t*
bser_parse_from_file(FILE* fp, bser_t* fill)
{
    void* buf;
    uint8_t magic[2];
    int64_t size;

    if (fread(magic, 1, 2, fp) != 2 ||
        magic[0] != 0 ||
        magic[1] != 1) {
        return new_error("Could not read bser magic values", fill);
    } else if (integer_from_file(fp, &size)) {
        return new_error("Could not read bser length", fill);
    } else if (size <= 0) {
        return new_error("Invalid bser length", fill);
    } else {
        buf = malloc(size);
        if (buf == NULL) {
            return new_error("Could not allocate memory to hold data", fill);
        } else if (fread(buf, 1, size, fp) != size) {
            return new_error("Could not read full bser data", fill);
        } else {
            return bser_parse_content(buf, size, fill);
        }
    }
}

static void
parse_array(bser_t* fill, bser_buffer_t* buffer)
{
     bser_t length;
     new_unparsed(buffer, &length);
     if (bser_is_integer(&length)) {
        size_t sz = (size_t)bser_integer_value(&length);
        bser_t* array = malloc(sizeof(*array) * sz);
        if (array == NULL) {
            new_error("Could not allocate enough memory to hold "
                      "array elements", fill);
        } else {
            for (int i = 0; i < sz; ++i) {
                new_unparsed(buffer, &array[i]);
            }
            bser_new_array(array, sz, fill);
        }
     } else {
        new_error("Array does not have an integer length", fill);
     }
}

static void
parse_object(bser_t* fill, bser_buffer_t* buffer)
{
     bser_t length;
     new_unparsed(buffer, &length);
     if (bser_is_integer(&length)) {
        size_t sz = (size_t)bser_integer_value(&length);
        bser_key_value_pair_t* array = malloc(sizeof(*array) * sz);
        if (array == NULL) {
            new_error("Could not allocate enough memory to hold "
                      "object fields", fill);
        } else {
            for (int i = 0; i < sz; ++i) {
                new_unparsed(buffer, &array[i].key);
                new_unparsed(buffer, &array[i].value);
            }
            bser_new_object(array, sz, fill);
        }
     } else {
        new_error("Object does not have an integer length", fill);
     }
}

static void
parse_string(bser_t* fill, bser_buffer_t* buffer)
{
     bser_t length;
     new_unparsed(buffer, &length);
     if (bser_is_integer(&length)) {
        size_t sz = (size_t)bser_integer_value(&length);
        const char* chars = (const char*)buffer->data + buffer->cursor;
        buffer->cursor += sz;
        bser_new_string(chars, sz, fill);
     } else {
        new_error("String does not have an integer length", fill);
     }
}

static void
parse_compact_array(bser_t* fill, bser_buffer_t* buffer)
{
    bser_t header;
    new_unparsed(buffer, &header);
    if (bser_is_array(&header)) {
        size_t header_length = bser_array_size(&header);
        for (int i = 0; i < header_length; ++i) {
            bser_parse_if_necessary(bser_array_get(&header, i));
        }
        bser_t length;
        new_unparsed(buffer, &length);
        if (bser_is_integer(&length)) {
            size_t sz = (size_t)bser_integer_value(&length);
            bser_t* array = malloc(sizeof(*array) * sz);
            if (array == NULL) {
                new_error("Could not allocate enough memory to hold "
                          "compact array elements", fill);
            } else {
                bser_new_array(array, sz, fill);
                for (int i = 0; i < sz; ++i) {
                    new_compact_object(buffer, &header, &array[i]);
                }
            }
        } else {
            new_error("Compact array does not have an integer length", fill);
        }
    } else {
        new_error("Compact array does not have a header array", fill);
    }
    bser_free_contents(&header);
}

void
bser_parse_generic(bser_t* fill, bser_buffer_t* buffer)
{
    if (buffer->cursor >= buffer->datalen) {
        fill->type = BSER_TAG_ERROR;
        fill->value.error_message = "out of data";
    } else {
        uint8_t* as_int = buffer->data;
        uint8_t tag = as_int[buffer->cursor++];
        void* data = (char *)buffer->data + buffer->cursor;

        switch (tag) {
            case BSER_TAG_ARRAY:
                parse_array(fill, buffer);
                break;
            case BSER_TAG_OBJECT:
                parse_object(fill, buffer);
                break;
            case BSER_TAG_STRING:
                parse_string(fill, buffer);
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
                parse_compact_array(fill, buffer);
                break;
            case BSER_TAG_NO_FIELD:
                fill->type = BSER_TAG_NO_FIELD;
                break;
            default:
                new_error("unknown tag in data stream", fill);
                break;
        }
    }
}

static int
is_fully_parsed(bser_t* bser)
{
    size_t index;
    if (bser_is_unparsed(bser)) {
        return 0;
    } else if (bser_is_array(bser) && (index = bser_array_size(bser)) > 0) {
        return is_fully_parsed(&bser->value.array.elements[index - 1]);
    } else if (bser_is_object(bser) && (index = bser_object_size(bser)) > 0) {
        return is_fully_parsed(&bser->value.object.fields[index - 1].value);
    }
    return 1;
}

static void
fully_parse(bser_t* bser)
{
    bser_parse_if_necessary(bser);

    if (!is_fully_parsed(bser)) {
        if (bser_is_array(bser)) {
            for (int i = 0; i < bser->value.array.length; ++i) {
                fully_parse(&bser->value.array.elements[i]);
            }
        } else if (bser_is_object(bser)) {
            for (int i = 0; i < bser->value.object.length; ++i) {
                struct bser_key_value_pair* pair =
                    &bser->value.object.fields[i];
                bser_parse_if_necessary(&pair->key);
                fully_parse(&pair->value);
            }
        }
    }
}

void
bser_parse_array_elements_to(bser_t* array, size_t limit)
{
    assert(bser_is_array(array));
    if (limit > 0) {
        /* Search back to find first parsed, and parse all from there */
        size_t index = limit - 1;
        while (!is_fully_parsed(&array->value.array.elements[index]) && index > 0) {
            --index;
        }
        for (int i = index; i < limit; ++i) {
            fully_parse(&array->value.array.elements[i]);
        }
    }
}

void
bser_parse_object_fields_to(bser_t* obj, size_t limit)
{
    assert(bser_is_object(obj));
    if (limit > 0) {
        /* Search back to find first parsed, and parse all from there */
        size_t index = limit - 1;
        while (!is_fully_parsed(&obj->value.object.fields[index].value) &&
               index > 0) {
            --index;
        }

        for (int i = index; i < limit; ++i) {
            bser_key_value_pair_t* pair = bser_object_pair_at(obj, i);
            bser_parse_if_necessary(&pair->key);
            fully_parse(&pair->value);
        }
    }
}
