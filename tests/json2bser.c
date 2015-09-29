#include <stdio.h>

#include <jansson.h>

#include "bser_write.h"

int main(int argc, char* argv[]) {
    json_error_t error;
#if JANSSON_VERSION_HEX >= 0x020600
    json_object_seed(1); /* make test results repeatable */
#endif
    json_t* root = json_loadf(stdin, 0, &error);
    if (root == NULL) {
        fprintf(stderr, "Parse error: %s\n  at %s line %d col %d\n",
            error.text, error.source, error.line, error.column);
    } else {
        int ret = bser_write_to_file(root, stdout);
        fprintf(stderr, "Wrote %d bytes\n", ret);
    }
}
