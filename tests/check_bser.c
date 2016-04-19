#include <assert.h>
#include <check.h>
#include <stdlib.h>

#include <jansson.h>
#include "bser.h"
#include "bser_parse.h"
#include "bser_write.h"

void
setup(void)
{
}

void
teardown(void)
{
}

START_TEST(test_bser_parse_simple)
{
    uint8_t buffer[] = { 0x03, 0x42 };
    bser_t* bser = bser_parse_content(buffer, sizeof(buffer), NULL);
    ck_assert_msg(bser != NULL && !bser_is_error(bser), "Parse error");
    ck_assert_msg(bser_is_integer(bser), "Did not parse integer");
    ck_assert_msg(bser_integer_value(bser) == 0x42, "Parsed wrong value");
    bser_free(bser);
}
END_TEST

START_TEST(test_bser_in_order_parse)
{
    json_error_t err;
    json_t* root = json_loads(
        "[ "
            "{ \"val\": 42, \"foo\": \"foo_value\", \"bar\": \"bar_value\" }, "
            "4, "
            "{ \"one\": 1, \"two\": 2, \"three\": 3, \"four\": 4 }, "
            "{ \"five\": 5, \"field\": \"field_value\" }, "
            "277 "
        "]", JSON_DISABLE_EOF_CHECK, &err);

    ck_assert_msg(root != NULL, "Parse error on input json");

    size_t content_size = bser_encoding_size(root);

    ck_assert_msg(content_size > 0, "Bad content byte count");

    size_t hdr_size = bser_header_size(content_size);
    size_t buf_size = hdr_size + content_size;
    uint8_t* buffer = malloc(buf_size);

    size_t wrote = bser_write_to_buffer(root, content_size, buffer, buf_size);
    json_decref(root);

    ck_assert_msg(wrote > 0, "Overflowed buffer");

    bser_t* bser = bser_parse_buffer(buffer, buf_size, NULL);
    ck_assert_msg(bser != NULL && !bser_is_error(bser), "Parse error");
    ck_assert_msg(bser_is_array(bser), "Did not parse root array");

    bser_t* item = bser_array_get(bser, 3);
    ck_assert_msg(item != NULL, "NULL item at array[3]");
    ck_assert_msg(bser_is_object(item), "Wrong type in array[3]");

    bser_t* five = bser_object_get(item, "five");
    ck_assert_msg(five != NULL, "NULL field 'five'");
    ck_assert_msg(bser_is_integer(five), "Wrong type in object");
    ck_assert_msg(bser_integer_value(five) == 5, "Wrong value in field in object 3");

    item = bser_array_get(bser, 0);
    ck_assert_msg(item != NULL, "NULL item at array[0]");
    ck_assert_msg(bser_is_object(item), "Wrong type in array[0]");
    bser_t* val = bser_object_get(item, "val");
    ck_assert_msg(val != NULL, "NULL field 'val'");
    ck_assert_msg(bser_integer_value(val) == 42, "Wrong value in object 0");

    item = bser_array_get(bser, 1);
    ck_assert_msg(bser_is_integer(item), "Wrong type in array[1]");
    ck_assert_msg(bser_integer_value(item) == 4, "Wrong value in array[1]");

    item = bser_array_get(bser, 4);
    ck_assert_msg(bser_is_integer(item), "Wrong type in array[4]");
    ck_assert_msg(bser_integer_value(item) == 277, "Wrong value in array[4]");

    bser_free(bser);
}
END_TEST

START_TEST(test_bser_in_order_parse_compact)
{
    json_error_t err;
    json_t* root = json_loads(
        "[ "
            "{ \"val\": 42, \"foo\": \"foo_value\", \"bar\": \"bar_value\" }, "
            "{ \"one\": 1, \"two\": 2, \"three\": 3, \"four\": 4 }, "
            "{ \"five\": 5, \"field\": \"field_value\" } "
        "]", JSON_DISABLE_EOF_CHECK, &err);

    ck_assert_msg(root != NULL, "Parse error on input json");

    size_t content_size = bser_encoding_size(root);

    ck_assert_msg(content_size > 0, "Bad content byte count");

    size_t hdr_size = bser_header_size(content_size);
    size_t buf_size = hdr_size + content_size;
    uint8_t* buffer = malloc(buf_size);
    size_t wrote = bser_write_to_buffer(root, content_size, buffer, buf_size);
    json_decref(root);

    ck_assert_msg(wrote > 0, "Overflowed buffer");

    bser_t* bser = bser_parse_buffer(buffer, buf_size, NULL);
    ck_assert_msg(bser != NULL && !bser_is_error(bser), "Parse error");
    ck_assert_msg(bser_is_array(bser), "Did not parse root array");

    bser_t* item = bser_array_get(bser, 2);
    ck_assert_msg(item != NULL, "NULL item at array[2]");
    ck_assert_msg(bser_is_object(item), "Wrong type in array[2]");

    bser_t* five = bser_object_get(item, "five");
    ck_assert_msg(five != NULL, "NULL field 'five'");
    ck_assert_msg(bser_is_integer(five), "Wrong type in object");
    ck_assert_msg(bser_integer_value(five) == 5, "Wrong value in object 2");

    item = bser_array_get(bser, 0);
    ck_assert_msg(item != NULL, "NULL item at array[0]");
    ck_assert_msg(bser_is_object(item), "Wrong type in array[0]");
    bser_t* val = bser_object_get(item, "val");
    ck_assert_msg(val != NULL, "NULL field 'val'");
    ck_assert_msg(bser_integer_value(val) == 42, "Wrong value in object 0");

    bser_free(bser);
}
END_TEST



Suite *
bser_suite(void)
{
    Suite *s = suite_create("Tests");

    /* Core test case */
    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_bser_parse_simple);
    tcase_add_test(tc_core, test_bser_in_order_parse);
    tcase_add_test(tc_core, test_bser_in_order_parse_compact);
    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = bser_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
