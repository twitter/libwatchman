#ifndef LIBWATCHMAN_BSER_PRIVATE_H_
#define LIBWATCHMAN_BSER_PRIVATE_H_

#include <stdint.h>
#include <stdlib.h>

enum {
    BSER_TAG_ARRAY         = 0x00,
    BSER_TAG_OBJECT        = 0x01,
    BSER_TAG_STRING        = 0x02,
    BSER_TAG_INT8          = 0x03,
    BSER_TAG_INT16         = 0x04,
    BSER_TAG_INT32         = 0x05,
    BSER_TAG_INT64         = 0x06,
    BSER_TAG_REAL          = 0x07,
    BSER_TAG_TRUE          = 0x08,
    BSER_TAG_FALSE         = 0x09,
    BSER_TAG_NULL          = 0x0a,
    BSER_TAG_COMPACT_ARRAY = 0x0b,
    BSER_TAG_NO_FIELD      = 0x0c,
    BSER_TAG_UNPARSED      = 0x0d,
    BSER_TAG_ERROR         = 0x0e,
    BSER_NUM_TAGS          = 0x0f
};

typedef struct bser_buffer {
    uint8_t* data;
    size_t datalen;
    size_t cursor;
} bser_buffer_t;

struct bser_key_value_pair;
struct bser_buffer;

struct bser_unparsed {
    struct bser_buffer* buffer;
};

typedef struct bser {
    uint8_t type;
    union {
        uint64_t integer;
        double real;
        struct {
           const char* chars;
           size_t length;
        } string;
        struct {
            struct bser* elements;
            size_t length;
        } array;
        struct {
            struct bser_key_value_pair* fields;
            size_t length;
        } object;
        struct bser_unparsed unparsed;
        const char* error_message;
    } value;
} bser_t;

typedef struct bser_key_value_pair {
    struct bser key;
    struct bser value;
} bser_key_value_pair_t;

static inline bser_t* bser_alloc(void)
{
    return (bser_t*)malloc(sizeof(bser_t));
}

void bser_parse_generic(bser_t* fill, struct bser_buffer* buffer);

static inline void bser_parse_if_necessary(bser_t* bser)
{
    if (bser->type == BSER_TAG_UNPARSED) {
        bser_parse_generic(bser, bser->value.unparsed.buffer);
    }
}

static inline int bser_is_unparsed(bser_t* bser)
{
    return bser->type == BSER_TAG_UNPARSED;
}
static inline int bser_is_no_field(bser_t* bser)
{
    return bser->type == BSER_TAG_NO_FIELD;
}

void bser_parse_array_elements_to(struct bser* array, size_t limit);
void bser_parse_object_fields_to(struct bser* array, size_t limit);

static inline bser_key_value_pair_t* bser_object_pair_at(
    struct bser* bser, size_t index)
{
    return &bser->value.object.fields[index];
}

#endif /* ndef LIBWATCHMAN_BSER_PRIVATE_H_ */
