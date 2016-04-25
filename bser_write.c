#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "bser.h"
#include "bser_write.h"

#define SIZE_U8 sizeof(uint8_t)
#define SIZE_S8 sizeof(int8_t)
#define SIZE_S16 sizeof(int16_t)
#define SIZE_S32 sizeof(int32_t)
#define SIZE_S64 sizeof(int64_t)
#define SIZE_DBL sizeof(double)
#define SIZE_MAGIC sizeof(char[2])

/* Interface for writing to a stream using a file or char[], or null */
typedef struct stream {
    /* Returns the number bytes were successfully written to the stream */
    size_t (*write)(struct stream*, const void* buffer, size_t bytes);
} stream_t;

static size_t write_json(json_t* json, stream_t* stream);

static size_t
write_integer(json_t* json, stream_t* stream)
{
    uint8_t tag;
    size_t bytes = 0;

    assert(json_is_integer(json));
    json_int_t v = json_integer_value(json);

    int8_t i8 = (int8_t)v;
    if (i8 == v) {
        tag = BSER_TAG_INT8;
        if (stream->write(stream, &tag, SIZE_U8) == SIZE_U8 &&
            stream->write(stream, &i8, SIZE_S8) == SIZE_S8) {
            bytes = SIZE_U8 + SIZE_S8;
        }
    } else {
        int16_t i16 = (int16_t)v;
        if (i16 == v) {
            tag = BSER_TAG_INT16;
            if (stream->write(stream, &tag, SIZE_U8) == SIZE_U8 &&
                stream->write(stream, &i16, SIZE_S16) == SIZE_S16) {
                bytes = SIZE_U8 + SIZE_S16;
            }
        } else {
            int32_t i32 = (int32_t)v;
            if (i32 == v) {
                tag = BSER_TAG_INT32;
                if (stream->write(stream, &tag, SIZE_U8) == SIZE_U8 &&
                    stream->write(stream, &i32, SIZE_S32) == SIZE_S32) {
                    bytes = SIZE_U8 + SIZE_S32;
                }
            } else {
                tag = BSER_TAG_INT64;
                if (stream->write(stream, &tag, SIZE_U8) == SIZE_U8 &&
                    stream->write(stream, &v, SIZE_S64) == SIZE_S64) {
                    bytes = SIZE_U8 + SIZE_S64;
                }
            }
        }
    }
    return bytes;
}

static size_t
write_string(json_t* json, stream_t* stream)
{
    size_t bytes = 0;
    assert(json_is_string(json));
    const char* chars = json_string_value(json);
    size_t len = strlen(chars);
    uint8_t tag = BSER_TAG_STRING;

    if (stream->write(stream, &tag, SIZE_U8) == SIZE_U8) {
        json_t* length_node = json_integer(len);
        size_t len_bytes = write_integer(length_node, stream);
        json_decref(length_node);
        if (len_bytes > 0 &&
            stream->write(stream, chars, len) == len) {
            bytes = SIZE_U8 + len_bytes + len;
        }
    }
    return bytes;
}

static size_t
write_object(json_t* json, stream_t* stream)
{
    uint8_t tag = BSER_TAG_OBJECT;
    size_t bytes = 0;

    assert(json_is_object(json));

    if (stream->write(stream, &tag, SIZE_U8) == SIZE_U8) {
        size_t total_bytes = SIZE_U8;

        json_t* length_node = json_integer(json_object_size(json));
        size_t integer_length = write_integer(length_node, stream);
        total_bytes += integer_length;
        json_decref(length_node);

        if (integer_length > 0) {
            size_t val_bytes = 1;
            void *iter = json_object_iter(json);

            while (iter != NULL && val_bytes > 0) {
                val_bytes = 0;

                json_t* key_node = json_string(json_object_iter_key(iter));
                size_t key_bytes = write_string(key_node, stream);
                total_bytes += key_bytes;
                json_decref(key_node);

                if (key_bytes > 0) {
                    json_t* value = json_object_iter_value(iter);
                    val_bytes = write_json(value, stream);
                    total_bytes += val_bytes;
                }
                iter = json_object_iter_next(json, iter);
            }
            if (iter == NULL) {
                bytes = total_bytes;
            }
        }
    }
    return bytes;
}

static int
can_be_compact_array(json_t* json)
{
    assert(json_is_array(json));
    size_t length = json_array_size(json);

    int is_all_objects = 1;
    for (int i = 0; i < length && is_all_objects; ++i) {
        json_t* elem = json_array_get(json, i);
        is_all_objects &= json_is_object(elem);
    }
    return length > 1 && is_all_objects;
}

static int
string_array_contains(json_t* array, const char* string)
{
    assert(json_is_array(array));
    int is_present = 0;
    for (int i = 0; i < json_array_size(array) && is_present == 0; ++i) {
        json_t* str = json_array_get(array, i);
        assert(json_is_string(str));
        is_present = !strcmp(json_string_value(str), string);
    }
    return is_present;
}

static json_t*
build_compact_array_header(json_t* json)
{
    assert(json_is_array(json));
    size_t length = json_array_size(json);
    json_t* compact_header = json_array();

    for (int i = 0; i < length; ++i) {
        json_t* obj = json_array_get(json, i);
        assert(json_is_object(obj));

        void* iter = json_object_iter(obj);
        while (iter) {
            const char* key = json_object_iter_key(iter);
            if (!string_array_contains(compact_header, key)) {
                json_array_append_new(compact_header, json_string(key));
            }
            iter = json_object_iter_next(obj, iter);
        }
    }
    return compact_header;
}

static size_t
write_array(json_t* json, stream_t* stream);

static size_t
write_compact_object(json_t* object, json_t* header, stream_t* stream)
{
    size_t bytes = 0;
    size_t field_bytes = 1;
    size_t fields_bytes = 0;
    int i;

    assert(json_is_array(header));
    size_t header_length = json_array_size(header);

    for (i = 0; i < header_length && field_bytes > 0; ++i) {
        const char* key = json_string_value(json_array_get(header, i));
        json_t* value = json_object_get(object, key);

        if (value == NULL) {
            uint8_t no_field_tag = BSER_TAG_NO_FIELD;
            field_bytes = stream->write(stream, &no_field_tag, SIZE_U8);
        } else {
            field_bytes = write_json(value, stream);
        }
        fields_bytes += field_bytes;
    }
    if (i == header_length) {
        bytes = fields_bytes;
    }

    return bytes;
}

static size_t
write_compact_objects(json_t* objects, json_t* header, stream_t* stream)
{
    size_t bytes = 0;
    size_t obj_bytes = 1;
    size_t objs_bytes = 0;
    int i;

    assert(json_is_array(objects));
    size_t array_length = json_array_size(objects);

    for (i = 0; i < array_length && obj_bytes > 0; ++i) {
        json_t* obj = json_array_get(objects, i);

        obj_bytes = write_compact_object(obj, header, stream);
        objs_bytes += obj_bytes;
    }

    if (i == array_length) {
        bytes = objs_bytes;
    }
    return bytes;
}

static size_t
write_compact_array(json_t* array, stream_t* stream)
{
    size_t bytes = 0;

    assert(json_is_array(array));
    json_t* header = build_compact_array_header(array);

    uint8_t tag = BSER_TAG_COMPACT_ARRAY;
    if (stream->write(stream, &tag, SIZE_U8) == SIZE_U8) {
        size_t header_bytes = write_array(header, stream);
        if (header_bytes > 0) {
            size_t array_length = json_array_size(array);

            json_t* array_length_node = json_integer(array_length);
            size_t integer_size = write_integer(array_length_node, stream);
            if (integer_size > 0) {
                size_t written = write_compact_objects(array, header, stream);
                if (written > 0) {
                    bytes = SIZE_U8 + header_bytes + integer_size + written;
                }
            }
            json_decref(array_length_node);
        }
    }
    json_decref(header);
    return bytes;
}

static size_t
write_array(json_t* json, stream_t* stream)
{
    size_t bytes = 0;

    if (can_be_compact_array(json)) {
        bytes = write_compact_array(json, stream);
    } else {
        uint8_t tag = BSER_TAG_ARRAY;
        if (stream->write(stream, &tag, SIZE_U8) == SIZE_U8) {
            size_t int_bytes;

            size_t length = json_array_size(json);
            json_t* length_node = json_integer(length);

            int_bytes = write_integer(length_node, stream);
            json_decref(length_node);

            if (int_bytes > 0) {
                int i;
                size_t elem_bytes = 1;
                size_t elems_bytes = 0;

                for (i = 0; i < length && elem_bytes > 0; ++i) {
                    elem_bytes = write_json(json_array_get(json, i), stream);
                    elems_bytes += elem_bytes;
                }

                if (i == length) {
                    bytes = SIZE_U8 + int_bytes + elems_bytes;
                }
            }
        }
    }
    return bytes;
}

static size_t
write_real(json_t* json, stream_t* stream)
{
    uint8_t op = BSER_TAG_REAL;
    assert(json_is_real(json));
    double val = json_real_value(json);
    size_t bytes = 0;

    if (stream->write(stream, &op, SIZE_U8) == SIZE_U8) {
        if (stream->write(stream, &val, SIZE_DBL) == SIZE_DBL) {
            bytes = SIZE_U8 + SIZE_DBL;
        }
    }
    return bytes;
}

static size_t
write_true(json_t* json, stream_t* stream)
{
    uint8_t op = BSER_TAG_TRUE;
    return stream->write(stream, &op, SIZE_U8);
}

static size_t
write_false(json_t* json, stream_t* stream)
{
    uint8_t op = BSER_TAG_FALSE;
    return stream->write(stream, &op, SIZE_U8);
}

static size_t
write_null(json_t* json, stream_t* stream)
{
    uint8_t op = BSER_TAG_NULL;
    return stream->write(stream, &op, SIZE_U8);
}

static size_t
write_json(json_t* json, stream_t* stream)
{
    switch (json_typeof(json)) {
        case JSON_OBJECT:  return write_object(json, stream);
        case JSON_ARRAY:   return write_array(json, stream);
        case JSON_STRING:  return write_string(json, stream);
        case JSON_INTEGER: return write_integer(json, stream);
        case JSON_REAL:    return write_real(json, stream);
        case JSON_TRUE:    return write_true(json, stream);
        case JSON_FALSE:   return write_false(json, stream);
        case JSON_NULL:    return write_null(json, stream);
        default:           return 0;
    }
}

/* Null stream is used to count the number of bytes that would be written. */
struct null_stream {
    stream_t stream;
};

static size_t
null_stream_write(stream_t* s, const void* data, size_t nb)
{
    return nb;
}

/* For writing to a memory buffer stream */
struct buffer_stream {
    stream_t stream;
    bser_buffer_t buffer;
};

static size_t
buffer_stream_write(stream_t* s, const void* data, size_t nb)
{
    size_t result = 0;

    struct buffer_stream* stream = (struct buffer_stream*)s;

    if (stream->buffer.cursor + nb <= stream->buffer.datalen) {
        memcpy(&stream->buffer.data[stream->buffer.cursor], data, nb);
        stream->buffer.cursor += nb;
        result = nb;
    }
    return result;
}

/* For writing a FILE stream */
struct file_stream {
    stream_t stream;
    FILE* file;
    size_t position;
};

static size_t
file_stream_write(stream_t* s, const void* data, size_t nb)
{
    struct file_stream* stream = (struct file_stream*)s;
    size_t count = fwrite(data, SIZE_U8, nb, stream->file);
    if (count == nb) {
        stream->position += nb;
        return nb;
    } else {
        return 0;
    }
}

size_t
bser_encoding_size(json_t* node)
{
    struct null_stream stream;
    stream.stream.write = null_stream_write;

    return write_json(node, &stream.stream);
}

size_t
bser_header_size(size_t content_size) {
    json_t* node = json_integer(content_size);
    size_t sz = SIZE_MAGIC + bser_encoding_size(node);
    json_decref(node);

    return sz;
}

static size_t
write_header(size_t content_size, stream_t* stream)
{
    const uint8_t magic[] = { 0x00, 0x01 };
    size_t node_bytes;

    json_t* content_size_node = json_integer(content_size);

    if (stream->write(stream, magic, SIZE_MAGIC) == SIZE_MAGIC &&
        (node_bytes = write_json(content_size_node, stream)) > 0) {
        return SIZE_MAGIC + node_bytes;
    } else {
        return 0;
    }
}

static size_t
write_pdu(json_t* root, size_t content_size, stream_t* stream)
{
    size_t hdr_bytes;
    size_t content_bytes;

    if ((hdr_bytes = write_header(content_size, stream)) > 0 &&
        (content_bytes = write_json(root, stream)) == content_size) {
        return hdr_bytes + content_bytes;
    } else {
        return 0;
    }
}


size_t
bser_write_to_buffer(
    json_t* root, size_t content_size, void* buffer, size_t buflen)
{
    struct buffer_stream stream;

    assert(buffer != NULL);

    stream.stream.write = buffer_stream_write;
    stream.buffer.data = buffer;
    stream.buffer.datalen = buflen;
    stream.buffer.cursor = 0;

    return write_pdu(root, content_size, &stream.stream);
}

size_t
bser_write_to_file(json_t* root, FILE* file)
{
    size_t content_size;
    size_t bytes;
    struct file_stream stream;

    assert(file != NULL);

    stream.stream.write = file_stream_write;
    stream.file = file;
    stream.position = 0;

    content_size = bser_encoding_size(root);
    bytes = write_pdu(root, content_size, &stream.stream);
    fflush(file);
    return bytes;
}
