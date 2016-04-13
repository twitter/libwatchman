#ifndef _LIBWATCHMAN_BSER_WRITE_H_
#define _LIBWATCHMAN_BSER_WRITE_H_

#include <stdio.h>
#include <stdint.h>
#include <jansson.h>

/*
 * Write JSON data in BSER format to a file or buffer.  Returns the
 * number of bytes that were written or would have been written.
 */

size_t bser_count_bytes(json_t* root);
size_t bser_write_to_buffer(json_t* root, uint8_t* buffer, size_t buflen);
size_t bser_write_to_file(json_t* root, FILE* file);

#endif /* ndef _LIBWATCHMAN_BSER_WRITE_H */
