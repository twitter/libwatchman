#ifndef LIBWATCHMAN_BSER_WRITE_H_
#define LIBWATCHMAN_BSER_WRITE_H_

#include <stdio.h>
#include <stdint.h>
#include <jansson.h>

/* Returns the number of bytes needed for encoding 'node'.  Does not include
 * any header */
size_t bser_encoding_size(json_t* node);

/* Size of the header needed for content of size 'content_size' */
size_t bser_header_size(size_t content_size);

/* Write JSON data in BSER format to a memory buffer, including a header with
 * the magic value and the content size.  Returns the number of bytes that were
 * written, 0 on error. */
size_t bser_write_to_buffer(
    json_t* root, size_t content_size, uint8_t* buffer, size_t buflen);

/* Write JSON data in BSER format to a FILE, including a header with the magic
 * value and the content size.  Returns the number of bytes that were written,
 * 0 on error. */
size_t bser_write_to_file(json_t* root, FILE* file);

#endif /* ndef LIBWATCHMAN_BSER_WRITE_H */
