#include <stdio.h>
#include <stdint.h>

#include <jansson.h>

#include "bser_parse.h"

int main(int argc, char* argv[]) {
#if JANSSON_VERSION_HEX >= 0x020600
    json_object_seed(1); /* make test results repeatable */
#endif
    bser_t bser;
    bser_parse_from_file(stdin, &bser);
    json_t* root = bser2json(&bser);
    if (root == NULL) {
        fprintf(stderr, "Could not convert BSER\n");
    } else {
        json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENCODE_ANY);
        fprintf(stdout, "\n");
    }
}
