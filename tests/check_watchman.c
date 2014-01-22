#include "../watchman.h"
#include <assert.h>
#include <check.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

char test_dir[L_tmpnam];

void setup(void)
{
	assert(tmpnam(test_dir));
	mode_t mode = 0700;
	if (mkdir(test_dir, mode)) {
		perror("Couldn't make test directory");
		exit(1);
	}
}

void teardown(void)
{
	DIR* dh = opendir(test_dir);
	struct dirent *cur;
	char path[256 + L_tmpnam + 2];
	int test_dir_len = strlen(test_dir);
	strcpy(path, test_dir);
	path[test_dir_len] = '/';
	while (cur = readdir(dh)) {
		if (strcmp(cur->d_name, ".") || strcmp(cur->d_name, "..")) {
			strcpy(path + test_dir_len + 1, cur->d_name);
			unlink(path);
		}
	}
	closedir(dh);
	if (rmdir(test_dir)) {
		perror("Couldn't remove test directory");
		exit(1);
	}
}

START_TEST (test_watchman_connect)
{
	watchman_error_t error;
	watchman_connection_t *conn = watchman_connect(&error);
	ck_assert_msg(conn != NULL, error.message);
	ck_assert_msg(!watchman_watch(conn, test_dir, &error),
		      error.message);

	watchman_watch_list_t* watched;
	watched = watchman_watch_list(conn, &error);
	ck_assert_msg(watched != NULL, error.message);

	int found = 0;
	int i;
	for (i = 0; i < watched->nr; ++i) {
		if (!strcmp(watched->roots[i], test_dir)) {
			found = 1;
		}
	}
	ck_assert_msg(found, "Dir we just started watching is not in watch-list");
	watchman_free_watch_list(watched);

	ck_assert_msg(!watchman_watch_del(conn, test_dir, &error),
		      error.message);

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

void create_file(char* filename, char* body) {
	int test_dir_len = strlen(test_dir);
	char* path = malloc(test_dir_len + strlen(filename) + 2);
	strcpy(path, test_dir);
	path[test_dir_len] = '/';
	strcpy(path + test_dir_len + 1, filename);
	FILE *fp = fopen(path, "a");
	fwrite(body, strlen(body), 1, fp);
	fclose(fp);
	free(path);

}

START_TEST (test_watchman_watch)
{
	watchman_error_t error;
	watchman_connection_t *conn = watchman_connect(&error);
	ck_assert_msg(conn != NULL, error.message);
	ck_assert_msg(!watchman_watch(conn, test_dir, &error),
		      error.message);

	watchman_expression_t *since;
	since = watchman_since_expression_time_t(0, 0);
	/* we expect to get nothing back from this one */
	watchman_query_result_t *result =
		watchman_query(conn, test_dir, since, WATCHMAN_FIELD_NAME,
			       &error);
	ck_assert_int_eq(0, result->nr);
	char* clock = strdup(result->clock);
	watchman_free_query_result(result);
	watchman_free_expression(since);

	create_file("morx", "abcde");

	/* now that we have created a file, check again */
	since = watchman_since_expression(clock, 0);
	result = watchman_query(conn, test_dir, since, WATCHMAN_FIELD_NAME,
				&error);
	ck_assert_msg(result != NULL, error.message);
	ck_assert_int_eq(1, result->nr);
	ck_assert_str_eq("morx", result->stats[0].name);
	watchman_free_query_result(result);
	watchman_free_expression(since);
	free(clock);

	ck_assert_msg(!watchman_watch_del(conn, test_dir, &error),
		      error.message);
	watchman_connection_close(conn);
}
END_TEST

START_TEST (test_watchman_misc)
{
	watchman_expression_t *expressions[3];
	expressions[0] = watchman_since_expression_time_t(0, 0);
	expressions[1] = watchman_since_expression_time_t(1, 0);
	expressions[2] = watchman_since_expression_time_t(2, 0);

	watchman_expression_t *all;
	all = watchman_allof_expression(3, expressions);
	watchman_free_expression(all);
}
END_TEST

 Suite *
 watchman_suite (void)
 {
   Suite *s = suite_create ("Tests");

   /* Core test case */
   TCase *tc_core = tcase_create ("Core");
   tcase_add_checked_fixture (tc_core, setup, teardown);
   tcase_add_test (tc_core, test_watchman_connect);
   tcase_add_test (tc_core, test_watchman_watch);
   tcase_add_test (tc_core, test_watchman_misc);
   suite_add_tcase (s, tc_core);

   return s;
 }

 int
 main (void)
 {
   int number_failed;
   Suite *s = watchman_suite ();
   SRunner *sr = srunner_create (s);
   srunner_run_all (sr, CK_NORMAL);
   number_failed = srunner_ntests_failed (sr);
   srunner_free (sr);
   return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
 }
