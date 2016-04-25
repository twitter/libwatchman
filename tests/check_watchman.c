#include "../watchman.h"
#include <assert.h>
#include <check.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

char test_dir[L_tmpnam];

void
setup(void)
{
    assert(tmpnam(test_dir));
    mode_t mode = 0700;
    if (mkdir(test_dir, mode)) {
        perror("Couldn't make test directory");
        exit(1);
    }
}

static int
is_dir(char *path)
{
    struct stat statbuf;
    stat(path, &statbuf);
    return S_ISDIR(statbuf.st_mode);
}

static void
rmdir_recursive(char *dir)
{
    DIR *dh = opendir(dir);
    struct dirent *cur;
    int dir_len = strlen(dir);
    char path[256 + dir_len + 2];
    strcpy(path, dir);
    path[dir_len] = '/';
    while ((cur = readdir(dh))) {
        if (strcmp(cur->d_name, ".") && strcmp(cur->d_name, "..")) {
            strcpy(path + dir_len + 1, cur->d_name);
            if (is_dir(path)) {
                rmdir_recursive(path);
                rmdir(path);
            } else {
                unlink(path);
            }
        }
    }
    closedir(dh);
    if (rmdir(dir)) {
        perror("Couldn't remove test directory");
        exit(1);
    }
}

void
teardown(void)
{
    rmdir_recursive(test_dir);
}

START_TEST(test_watchman_connect_timeout_fails)
{
    struct watchman_error error;
    struct timeval tv = {0};
    tv.tv_usec = 1;
    struct watchman_connection *conn = watchman_connect(tv, &error);
    ck_assert_msg(conn == NULL, "Should have failed to connect");
}
END_TEST

START_TEST(test_watchman_connect_timeout_succeeds)
{
    struct watchman_error error;
    struct timeval tv = {0};
    tv.tv_sec = 10;
    struct watchman_connection *conn = watchman_connect(tv, &error);
    ck_assert_msg(conn != NULL, error.message);
    watchman_connection_close(conn);
}
END_TEST


START_TEST(test_watchman_connect)
{
    struct watchman_error error;
    struct timeval tv_zero = {0};
    struct watchman_connection *conn = watchman_connect(tv_zero, &error);
    ck_assert_msg(conn != NULL, error.message);
    ck_assert_msg(!watchman_watch(conn, test_dir, &error), error.message);

    struct watchman_watch_list *watched;
    watched = watchman_watch_list(conn, &error);
    ck_assert_msg(watched != NULL, error.message);

    struct stat buf;
    int status = lstat(test_dir, &buf);
    ck_assert_msg(status == 0, error.message);
    ino_t inode = buf.st_ino;

    int found = 0;
    int i;
    for (i = 0; i < watched->nr; ++i) {
        if (!strcmp(watched->roots[i], test_dir)) {
            found = 1;
            break;
        } else {
            /* Different paths may refer to the same directory -- check the inode */
            if ((lstat(watched->roots[i], &buf) == 0) && buf.st_ino == inode) {
                found = 1;
                break;
            }
        }
    }
    ck_assert_msg(found, "Dir we just started watching is not in watch-list");
    watchman_free_watch_list(watched);

    ck_assert_msg(!watchman_watch_del(conn, test_dir, &error), error.message);

    watched = watchman_watch_list(conn, &error);
    ck_assert_msg(watched != NULL, error.message);

    for (i = 0; i < watched->nr; ++i) {
        if (!strcmp(watched->roots[i], test_dir)) {
            ck_abort_msg("Dir we just stopped watching is in watch-list");
        }
    }

    watchman_free_watch_list(watched);

    watchman_connection_close(conn);
}
END_TEST

static void
create_file(char *filename, char *body)
{
    int test_dir_len = strlen(test_dir);
    char *path = malloc(test_dir_len + strlen(filename) + 2);
    strcpy(path, test_dir);
    path[test_dir_len] = '/';
    strcpy(path + test_dir_len + 1, filename);
    FILE *fp = fopen(path, "a");
    fwrite(body, strlen(body), 1, fp);
    fclose(fp);
    free(path);

}

static void
create_dir(char *dirname)
{
    int test_dir_len = strlen(test_dir);
    char *path = malloc(test_dir_len + strlen(dirname) + 2);
    strcpy(path, test_dir);
    path[test_dir_len] = '/';
    strcpy(path + test_dir_len + 1, dirname);
    ck_assert(mkdir(path, 0700) == 0);
    free(path);
}

START_TEST(test_watchman_watch)
{
    struct watchman_error error;
    struct timeval tv_zero = {0};
    struct watchman_connection *conn = watchman_connect(tv_zero, &error);
    ck_assert_msg(conn != NULL, error.message);
    ck_assert_msg(!watchman_watch(conn, test_dir, &error), error.message);

    struct watchman_expression *since;
    since = watchman_since_expression_time_t(0, 0);
    /* we expect to get nothing back from this one */
    struct watchman_query_result *result =
        watchman_do_query(conn, test_dir, NULL, since, &error);
    ck_assert_msg(result != NULL, error.message);
    ck_assert_int_eq(0, result->nr);
    char *clock = strdup(result->clock);
    watchman_free_query_result(result);
    watchman_free_expression(since);

    create_file("morx.jar", "abcde");

    /* now that we have created a file, check again */
    since = watchman_since_expression(clock, 0);
    free(clock);
    int fields = WATCHMAN_FIELD_NAME | WATCHMAN_FIELD_CTIME_F;
    struct watchman_query *query = watchman_query();
    watchman_query_add_suffix(query, "jar");
    watchman_query_set_fields(query, fields);
    result = watchman_do_query(conn, test_dir, query, since, &error);
    ck_assert_msg(result != NULL, error.message);
    ck_assert_int_eq(1, result->nr);
    ck_assert_str_eq("morx.jar", result->stats[0].name);
    ck_assert(result->stats[0].ctime_f > 1390436718.0);
    watchman_free_query_result(result);
    watchman_free_query(query);

    /* try with a file inside a directory, to check paths */

    create_dir("fleem");
    create_file("fleem/fleem.jar", "body");

    query = watchman_query();
    watchman_query_add_path(query, "fleem", 0);
    result = watchman_do_query(conn, test_dir, query, since, &error);
    ck_assert_msg(result != NULL, error.message);
    ck_assert_int_eq(1, result->nr);

    watchman_free_query(query);
    watchman_free_query_result(result);
    watchman_free_expression(since);

    ck_assert_msg(!watchman_watch_del(conn, test_dir, &error), error.message);
    watchman_connection_close(conn);
}
END_TEST

START_TEST(test_watchman_misc)
{
    struct watchman_error error;
    struct timeval tv_zero = {0};
    struct watchman_connection *conn = watchman_connect(tv_zero, &error);
    ck_assert_msg(!watchman_watch(conn, test_dir, &error), error.message);

    struct watchman_expression *expressions[9];
    expressions[0] = watchman_since_expression_time_t(0, 0);
    expressions[1] = watchman_since_expression_time_t(1, 0);
    expressions[2] = watchman_since_expression("c:123:45", 0);
    expressions[3] = watchman_exists_expression();
    expressions[4] =
        watchman_not_expression(watchman_suffix_expression(".jsp"));
    expressions[5] = watchman_imatch_expression(".jsp", 0);

    const char *names[] = { "morx", "fleem" };
    expressions[6] = watchman_names_expression(2, names, 0);
    expressions[7] = watchman_type_expression('D');
    expressions[8] = watchman_true_expression();

    struct watchman_expression *all;
    all = watchman_allof_expression(8, expressions);
    struct watchman_query_result *result =
        watchman_do_query(conn, test_dir, NULL, all, &error);
    ck_assert_msg(result != NULL, error.message);
    watchman_free_query_result(result);
    watchman_free_expression(all);

    ck_assert_msg(!watchman_watch_del(conn, test_dir, &error), error.message);
    watchman_connection_close(conn);
}
END_TEST

Suite *
watchman_suite(void)
{
    Suite *s = suite_create("Tests");

    /* Core test case */
    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_watchman_connect_timeout_fails);
    tcase_add_test(tc_core, test_watchman_connect_timeout_succeeds);
    tcase_add_test(tc_core, test_watchman_connect);
    tcase_add_test(tc_core, test_watchman_watch);
    tcase_add_test(tc_core, test_watchman_misc);
    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s = watchman_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
