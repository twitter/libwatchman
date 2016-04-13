#ifndef _LIBWATCHMAN_BSER_PARSE_H_
#define _LIBWATCHMAN_BSER_PARSE_H_

#include <stdint.h>
#include <jansson.h>

#include "bser.h"

/**
 * Fills in 'bser' with the top-level object parsed from a bser data buffer.
 * If fill is NULL, it will be allocated.
 */
bser_t* bser_parse(uint8_t* buffer, size_t buflen, bser_t* fill);

/**
 * Fills in 'bser' with top-level object parsed from a file.
 * If fill is NULL, it will be allocated.
 */
bser_t* bser_parse_from_file(FILE* file, bser_t* fill);

/**
 * Convert a BSER representation into a json (jansson) representation
 */
json_t* bser2json(bser_t* bser);

#endif /* ndef _LIBWATCHMAN_BSER_PARSE_H_ */
