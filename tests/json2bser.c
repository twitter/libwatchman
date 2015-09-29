#include <stdio.h>

#include <jansson.h>

#include "bser_write.h"

int main(int argc, char* argv[]) {
    json_error_t error;
    json_object_seed(1); /* make test results repeatable */
    json_t* root = json_loadf(stdin, JSON_DECODE_ANY, &error);
    if (root == NULL) {
        fprintf(stderr, "Parse error: %s\n  at %s line %d col %d\n",
            error.text, error.source, error.line, error.column);
    } else {
        int ret = bser_write_to_file(root, stdout);
        fprintf(stderr, "Wrote %d bytes\n", ret);
    }
}
