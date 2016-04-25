#ifndef LIBWATCHMAN_BSER_PARSE_H_
#define LIBWATCHMAN_BSER_PARSE_H_

#include <stdint.h>

#include "bser.h"

/* Fills in 'bser' with the top-level object parsed from a bser data buffer.
 * If 'fill' is NULL, it will be allocated. */
bser_t* bser_parse_content(void* buffer, size_t buflen, bser_t* fill);

/* Fills in 'bser' with the top-level object parsed from a bser PDU.  The
 * header must start with a '\00' '\01' and then contain a bser-encoded
 * integer which indicates the length of the content data. */
bser_t* bser_parse_buffer(void* buffer, size_t buflen, bser_t* fill);

/* Fills in 'bser' with top-level object parsed from a PDU read from a file.
 * If 'fill' is NULL, it will be allocated.  */
bser_t* bser_parse_from_file(FILE* file, bser_t* fill);

#endif /* ndef LIBWATCHMAN_BSER_PARSE_H_ */
