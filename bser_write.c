#include <string.h>
#include <stdarg.h>

#include "bser_write.h"
#include "bser_private.h"

/**
 * Interface for writing to a stream using a file or char[], or null
 */
typedef struct stream {
    /* Returns the number bytes were successfully written to the stream */
    size_t (*write)(struct stream*, const uint8_t* buffer, size_t nbytes);
} stream_t;

static size_t write_json(json_t* json, stream_t* stream);

static size_t write_integer(json_t* json, stream_t* stream) {
    uint8_t tag;
    json_int_t v = json_integer_value(json);
    size_t bytes = -1;

    int8_t i8 = (int8_t)v;
    if (i8 == v) {
        tag = BSER_TAG_INT8;
        if (stream->write(stream, &tag, 1) != -1 &&
            stream->write(stream, (uint8_t*)&i8, 1) != -1) {
            bytes = 2;
        }
    } else {
        int16_t i16 = (int16_t)v;
        if (i16 == v) {
            tag = BSER_TAG_INT16;
            if (stream->write(stream, &tag, 1) != -1 &&
                stream->write(stream, (uint8_t*)&i16, 2) != -1) {
                bytes = 3;
            }
        } else {
            int32_t i32 = (int32_t)v;
            if (i32 == v) {
                tag = BSER_TAG_INT32;
                if (stream->write(stream, &tag, 1) != -1 &&
                    stream->write(stream, (uint8_t*)&i32, 4) != -1) {
                    bytes = 5;
                }
            } else {
                tag = BSER_TAG_INT64;
                if (stream->write(stream, &tag, 1) != -1 &&
                    stream->write(stream, (uint8_t*)&v, 8) != -1) {
                    bytes = 9;
                }
            }
        }
    }
    return bytes;
}

static size_t write_string(json_t* json, stream_t* stream) {
    size_t bytes = -1;
    const char* chars = json_string_value(json);
    size_t len = strlen(chars);
    uint8_t tag = BSER_TAG_STRING;

    if (stream->write(stream, &tag, 1) != -1) {
        json_t* length_node = json_integer(len);
        size_t nbytes = write_integer(length_node, stream);
        json_decref(length_node);
        if (nbytes != -1 &&
            stream->write(stream, (uint8_t*)chars, len) != -1) {
            bytes = nbytes + len + 1;
        }
    }
    return bytes;
}

static size_t write_object(json_t* json, stream_t* stream) {
    uint8_t tag = BSER_TAG_OBJECT;
    size_t bytes = -1;

    if (stream->write(stream, &tag, 1) != -1) {
        size_t written_bytes = 1;

        json_t* length_node = json_integer(json_object_size(json));
        size_t integer_length = write_integer(length_node, stream);
        written_bytes += integer_length;
        json_decref(length_node);

        if (integer_length != -1) {
            size_t val_bytes = 0;
            void *iter = json_object_iter(json);

            while (iter != NULL && val_bytes != -1) {
                json_t* key_node = json_string(json_object_iter_key(iter));
                size_t key_bytes = write_string(key_node, stream);
                json_decref(key_node);

                if (key_bytes != -1) {
                    json_t* value = json_object_iter_value(iter);
                    val_bytes = write_json(value, stream);
                    if (val_bytes != -1) {
                        written_bytes += key_bytes + val_bytes;
                    }
                }
                iter = json_object_iter_next(json, iter);
            }
            if (iter == NULL) {
                bytes = written_bytes;
            }
        }
    }
    return bytes;
}

static int can_be_compact_array(json_t* json) {
    size_t length = json_array_size(json);

    int is_all_objects = 1;
    for (int i = 0; i < length && is_all_objects; ++i) {
        json_t* elem = json_array_get(json, i);
        is_all_objects &= json_is_object(elem);
    }
    return length > 1 && is_all_objects;
}

static int string_array_contains(json_t* array, const char* string) {
    int is_present = 0;
    for (int i = 0; i < json_array_size(array) && is_present == 0; ++i) {
        json_t* str = json_array_get(array, i);
        is_present = !strcmp(json_string_value(str), string);
    }
    return is_present;
}

static json_t* build_compact_array_header(json_t* json) {
    size_t length = json_array_size(json);
    json_t* compact_header = json_array();

    for (int i = 0; i < length; ++i) {
        const char* key;
        json_t* value;
        json_t* obj = json_array_get(json, i);

        json_object_foreach(obj, key, value) {
            if (!string_array_contains(compact_header, key)) {
                json_array_append_new(compact_header, json_string(key));
            }
        }
    }
    return compact_header;
}

static size_t write_array(json_t* json, stream_t* stream);

static size_t write_compact_object(json_t* object, json_t* header,
        stream_t* stream) {
    size_t bytes = -1;
    size_t field_bytes_written = 0;
    size_t fields_bytes_written = 0;
    int i;

    size_t header_length = json_array_size(header);

    for (i = 0; i < header_length && field_bytes_written != -1; ++i) {
        const char* key = json_string_value(json_array_get(header, i));
        json_t* value = json_object_get(object, key);

        if (value == NULL) {
            uint8_t no_field_tag = BSER_TAG_NO_FIELD;
            size_t status = stream->write(stream, &no_field_tag, 1);
            field_bytes_written = (status == 1) ? 1 : -1;
        } else {
            field_bytes_written = write_json(value, stream);
        }
        fields_bytes_written += field_bytes_written;
    }
    if (i == header_length) {
        bytes = fields_bytes_written;
    }

    return bytes;
}

static size_t write_compact_objects(json_t* objects, json_t* header,
        stream_t* stream) {
    size_t bytes = -1;
    size_t obj_bytes_written = 0;
    size_t objs_bytes_written = 0;
    int i;

    size_t array_length = json_array_size(objects);

    for (i = 0; i < array_length && obj_bytes_written != -1; ++i) {
        json_t* obj = json_array_get(objects, i);

        obj_bytes_written = write_compact_object(obj, header, stream);
        objs_bytes_written += obj_bytes_written;
    }

    if (i == array_length) {
        bytes = objs_bytes_written;
    }
    return bytes;
}

static size_t write_compact_array(json_t* array, stream_t* stream) {
    size_t bytes = -1;

    json_t* header = build_compact_array_header(array);

    uint8_t tag = BSER_TAG_COMPACT_ARRAY;
    size_t status = stream->write(stream, &tag, 1);
    if (status != -1) {
        size_t header_bytes = write_array(header, stream);
        if (header_bytes != -1) {
            size_t array_length = json_array_size(array);

            json_t* array_length_node = json_integer(array_length);
            size_t integer_size = write_integer(array_length_node, stream);
            if (integer_size != -1) {
                size_t data_written = write_compact_objects(array, header, stream);
                if (data_written != -1) {
                    bytes = 1 + header_bytes + integer_size + data_written;
                }
            }
            json_decref(array_length_node);
        }
    }
    json_decref(header);
    return bytes;
}

static size_t write_array(json_t* json, stream_t* stream) {
    size_t bytes = -1;

    if (can_be_compact_array(json)) {
        bytes = write_compact_array(json, stream);
    } else {
        uint8_t tag = BSER_TAG_ARRAY;
        size_t status = stream->write(stream, &tag, 1);
        if (status != -1) {
            size_t int_bytes;
            size_t total_bytes;

            size_t length = json_array_size(json);
            json_t* length_node = json_integer(length);

            int_bytes = write_integer(length_node, stream);
            json_decref(length_node);

            if (int_bytes != -1) {
                int i;
                size_t elem_nbytes = 0;
                total_bytes = int_bytes + 1;

                for (i = 0; i < length && elem_nbytes != -1; ++i) {
                    elem_nbytes = write_json(json_array_get(json, i), stream);
                    if (elem_nbytes != -1) {
                        total_bytes += elem_nbytes;
                    }
                }

                if (i == length) {
                    bytes = total_bytes;
                }
            }
        }
    }
    return bytes;
}

static size_t write_real(json_t* json, stream_t* stream) {
    uint8_t op = BSER_TAG_REAL;
    double val = json_real_value(json);
    size_t bytes = -1;

    size_t status = stream->write(stream, &op, 1);
    if (status != -1) {
        status = stream->write(stream, (uint8_t*)&val, sizeof(double));
        if (status != -1) {
            bytes = sizeof(double) + 1;
        }
    }
    return bytes;
}

static size_t write_true(json_t* json, stream_t* stream) {
    uint8_t op = BSER_TAG_TRUE;
    return stream->write(stream, &op, 1);
}

static size_t write_false(json_t* json, stream_t* stream) {
    uint8_t op = BSER_TAG_FALSE;
    return stream->write(stream, &op, 1);
}

static size_t write_null(json_t* json, stream_t* stream) {
    uint8_t op = BSER_TAG_NULL;
    return stream->write(stream, &op, 1);
}

static size_t write_json(json_t* json, stream_t* stream) {
    switch (json_typeof(json)) {
        case JSON_OBJECT:  return write_object(json, stream);
        case JSON_ARRAY:   return write_array(json, stream);
        case JSON_STRING:  return write_string(json, stream);
        case JSON_INTEGER: return write_integer(json, stream);
        case JSON_REAL:    return write_real(json, stream);
        case JSON_TRUE:    return write_true(json, stream);
        case JSON_FALSE:   return write_false(json, stream);
        case JSON_NULL:    return write_null(json, stream);
        default:           return -1;
    }
}

/**
 * A null stream which is just used the number of bytes that would be written.
 * Any reads just fail.
 */
struct null_stream {
    stream_t stream;
};

static size_t null_stream_write(stream_t* s, const uint8_t* data, size_t nb) {
    return nb;
}


/* Returns the number of bytes written, or -1 on error */
static int bser_write_to_stream(json_t* root, stream_t* stream) {
    const uint8_t magic[2] = { 0x00, 0x01 };
    size_t magic_sz = sizeof(magic);
    int result = -1;

    struct null_stream null_stream;
    null_stream.stream.write = null_stream_write;
    size_t pdu_sz = write_json(root, (stream_t*)&null_stream);
    json_t* pdu_sz_json = json_integer(pdu_sz);
    int size_sz;

    if (pdu_sz > 0 &&
        stream->write(stream, magic, magic_sz) == magic_sz &&
        (size_sz = write_json(pdu_sz_json, stream)) != -1 &&
        write_json(root, stream) == pdu_sz) {
        result = magic_sz + size_sz + pdu_sz;
    }

    json_decref(pdu_sz_json);
    return result;
}

/**
 * Writing to a buffer-based stream
 */
struct buffer_stream {
    stream_t stream;
    bser_buffer_t buffer;
};

static size_t buffer_stream_write(stream_t* s, const uint8_t* data, size_t nb) {
    size_t result = -1;

    struct buffer_stream* stream = (struct buffer_stream*)s;
    if (stream->buffer.cursor + nb < stream->buffer.datalen) {
        memcpy(&stream->buffer.data[stream->buffer.cursor], data, nb);
        stream->buffer.cursor += nb;
        result = nb;
    }
    return result;
}

/**
 * Writing a FILE-based stream
 */
struct file_stream {
    stream_t stream;
    FILE* file;
    size_t position;
};

static size_t file_stream_write(stream_t* s, const uint8_t* data, size_t nb) {
    struct file_stream* stream = (struct file_stream*)s;
    size_t count = fwrite((void*)data, 1, nb, stream->file);
    if (count == nb) {
        stream->position += nb;
        return nb;
    } else {
        return -1;
    }
}

size_t bser_count_bytes(json_t* root) {
    struct null_stream stream;
    stream.stream.write = null_stream_write;
    return bser_write_to_stream(root, &stream.stream);
}

size_t bser_write_to_buffer(json_t* root, uint8_t* buffer, size_t buflen) {
    struct buffer_stream stream;
    stream.stream.write = buffer_stream_write;
    stream.buffer.data = buffer;
    stream.buffer.datalen = buflen;
    stream.buffer.cursor = 0;

    return bser_write_to_stream(root, &stream.stream);
}

size_t bser_write_to_file(json_t* root, FILE* file) {
    struct file_stream stream;
    stream.stream.write = file_stream_write;
    stream.file = file;
    stream.position = 0;
    size_t res = bser_write_to_stream(root, &stream.stream);
    fflush(file);
    return res;
}
