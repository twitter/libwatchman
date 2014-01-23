#ifndef WATCHMAN_H
#define WATCHMAN_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>

enum watchman_fields {
	WATCHMAN_FIELD_NAME = 0x00000001,
	WATCHMAN_FIELD_EXISTS = 0x00000002,
	WATCHMAN_FIELD_CCLOCK = 0x00000004,
	WATCHMAN_FIELD_OCLOCK = 0x00000008,
	WATCHMAN_FIELD_CTIME = 0x00000010,
	WATCHMAN_FIELD_CTIME_MS = 0x00000020,
	WATCHMAN_FIELD_CTIME_US = 0x00000040,
	WATCHMAN_FIELD_CTIME_NS = 0x00000080,
	WATCHMAN_FIELD_CTIME_F = 0x00000100,
	WATCHMAN_FIELD_MTIME = 0x00000200,
	WATCHMAN_FIELD_MTIME_MS = 0x00000400,
	WATCHMAN_FIELD_MTIME_US = 0x00000800,
	WATCHMAN_FIELD_MTIME_NS = 0x00001000,
	WATCHMAN_FIELD_MTIME_F = 0x00002000,
	WATCHMAN_FIELD_SIZE = 0x00004000,
	WATCHMAN_FIELD_UID = 0x00008000,
	WATCHMAN_FIELD_GID = 0x00010000,
	WATCHMAN_FIELD_INO = 0x00020000,
	WATCHMAN_FIELD_DEV = 0x00040000,
	WATCHMAN_FIELD_NLINK = 0x00080000,
	WATCHMAN_FIELD_NEWER = 0x00100000, /* corresponds to "new" */
};
 
typedef struct {
	FILE* fp;
} watchman_connection_t;

enum watchman_expression_type {
	WATCHMAN_EXPR_TY_ALLOF,
	WATCHMAN_EXPR_TY_ANYOF,
	WATCHMAN_EXPR_TY_NOT,
	WATCHMAN_EXPR_TY_TRUE,
	WATCHMAN_EXPR_TY_FALSE,
	WATCHMAN_EXPR_TY_SINCE,
	WATCHMAN_EXPR_TY_SUFFIX,
	WATCHMAN_EXPR_TY_MATCH,
	WATCHMAN_EXPR_TY_IMATCH,
	WATCHMAN_EXPR_TY_PCRE,
	WATCHMAN_EXPR_TY_IPCRE,
	WATCHMAN_EXPR_TY_NAME,
	WATCHMAN_EXPR_TY_INAME,
	WATCHMAN_EXPR_TY_TYPE,
	WATCHMAN_EXPR_TY_EMPTY,
	WATCHMAN_EXPR_TY_EXISTS
};

typedef struct {
	char* message;
} watchman_error_t;

enum watchman_clockspec {
	WATCHMAN_CLOCKSPEC_DEFAULT = 0,
	WATCHMAN_CLOCKSPEC_OCLOCK,
	WATCHMAN_CLOCKSPEC_CCLOCK,
	WATCHMAN_CLOCKSPEC_MTIME,
	WATCHMAN_CLOCKSPEC_CTIME
};

enum watchman_basename {
	WATCHMAN_BASENAME_DEFAULT,
	WATCHMAN_BASENAME_BASENAME,
	WATCHMAN_BASENAME_WHOLENAME
};

typedef struct watchman_expression_t watchman_expression_t;

struct watchman_since_expr {
	int is_time_t;
	union {
		char* since;
		time_t time;
	} t;
	enum watchman_clockspec clockspec;
};

struct watchman_suffix_expr {
	char* suffix;
};

struct watchman_match_expr {
	char* match;
	enum watchman_basename basename;
};

struct watchman_name_expr {
	int nr;
	char** names;
	enum watchman_basename basename;
};

struct watchman_type_expr {
	char type;
};

struct watchman_not_expr {
	watchman_expression_t *clause;
};

struct watchman_union_expr {
	int nr;
	watchman_expression_t **clauses;
};

typedef struct {
	int exists;
	time_t ctime;
	int64_t ctime_ms;
	int64_t ctime_us;
	int64_t ctime_ns;
	double ctime_f;
	int dev;
	int gid;
	int ino;
	int mode;
	time_t mtime;
	int64_t mtime_ms;
	int64_t mtime_us;
	int64_t mtime_ns;
	double mtime_f;
	int newer;
	int nlink;
	int uid;
	char *name;
	char *oclock;
	char *cclock;
	size_t size;
} watchman_stat_t;

typedef struct {
	char *version;
	char *clock;
	int is_fresh_instance;

	int nr;
	watchman_stat_t *stats;
} watchman_query_result_t;

typedef struct {
	int nr;
	char **roots;
} watchman_watch_list_t;

struct watchman_expression_t {
	enum watchman_expression_type ty;
	union {
		struct watchman_union_expr union_expr;
		struct watchman_not_expr not_expr;
		struct watchman_since_expr since_expr;
		struct watchman_suffix_expr suffix_expr;
		struct watchman_match_expr match_expr;
		struct watchman_name_expr name_expr;
		struct watchman_type_expr type_expr;
		/* true, false, empty, and exists don't need any extra data */
	} e;
};

watchman_connection_t *watchman_connect(watchman_error_t *error);

int watchman_watch(watchman_connection_t *connection, const char *path, watchman_error_t *error);

int watchman_watch_del(watchman_connection_t *connection, const char *path, watchman_error_t *error);

watchman_watch_list_t* watchman_watch_list(watchman_connection_t *connection, watchman_error_t* error);


watchman_expression_t* watchman_since_expression(const char *since, enum watchman_clockspec spec);

watchman_expression_t* watchman_since_expression_time_t(time_t time, enum watchman_clockspec spec);

watchman_expression_t* watchman_not_expression(watchman_expression_t* expression);

watchman_expression_t* watchman_allof_expression(int nr, watchman_expression_t** expressions);

watchman_expression_t* watchman_anyof_expression(int nr, watchman_expression_t** expressions);

watchman_expression_t* watchman_empty_expression();

watchman_expression_t* watchman_true_expression();

watchman_expression_t* watchman_false_expression();

watchman_expression_t* watchman_exists_expression();

watchman_expression_t* watchman_suffix_expression(const char *suffix);

watchman_expression_t* watchman_match_expression(const char *match, enum watchman_basename basename);

watchman_expression_t* watchman_imatch_expression(const char *match, enum watchman_basename basename);

watchman_expression_t* watchman_pcre_expression(const char *match, enum watchman_basename basename);

watchman_expression_t* watchman_ipcre_expression(const char *match, enum watchman_basename basename);

watchman_expression_t* watchman_name_expression(const char *match, enum watchman_basename basename);

watchman_expression_t* watchman_iname_expression(const char *match, enum watchman_basename basename);

watchman_expression_t* watchman_names_expression(int nr, char const **match, enum watchman_basename basename);

watchman_expression_t* watchman_inames_expression(int nr, char const **match, enum watchman_basename basename);

watchman_expression_t* watchman_type_expression(char c);

watchman_query_result_t *watchman_query(watchman_connection_t *connection, const char *fs_path, const watchman_expression_t *expr, int fields, watchman_error_t *error);

void watchman_free_expression(watchman_expression_t *expr);

void watchman_free_query_result(watchman_query_result_t *res);

void watchman_free_watch_list(watchman_watch_list_t *list);

void watchman_connection_close(watchman_connection_t *connection);


#endif
