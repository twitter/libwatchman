#ifndef LIBWATCHMAN_WATCHMAN_H_
#define LIBWATCHMAN_WATCHMAN_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>


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
    WATCHMAN_FIELD_NEWER = 0x00100000,  /* corresponds to "new" */
    WATCHMAN_FIELD_MODE = 0x00200000,
    WATCHMAN_FIELD_END = 0x00400000
};

struct watchman_connection {
    FILE *fp;
};

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

struct watchman_error {
    char *message;
};

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

struct watchman_expression;

struct watchman_since_expr {
    unsigned is_str:1;
    union {
        char *since;
        time_t time;
    } t;
    enum watchman_clockspec clockspec;
};

struct watchman_suffix_expr {
    char *suffix;
};

struct watchman_match_expr {
    char *match;
    enum watchman_basename basename;
};

struct watchman_name_expr {
    int nr;
    char **names;
    enum watchman_basename basename;
};

struct watchman_type_expr {
    char type;
};

struct watchman_not_expr {
    struct watchman_expression *clause;
};

struct watchman_union_expr {
    int nr;
    struct watchman_expression **clauses;
};

/* These are the possible fields that can be returned by watchman
   query.  Only fields that you request will be set (if you don't
   request any, then watchman's default will be used). */
struct watchman_stat {
    time_t ctime;
    int64_t ctime_ms;
    int64_t ctime_us;
    int64_t ctime_ns;
    double ctime_f;
    dev_t dev;
    gid_t gid;
    int ino;
    int mode;
    time_t mtime;
    int64_t mtime_ms;
    int64_t mtime_us;
    int64_t mtime_ns;
    double mtime_f;
    unsigned newer:1;
    unsigned exists:1;
    int nlink;
    uid_t uid;
    char *name;
    char *oclock;
    char *cclock;
    off_t size;
};

struct watchman_query_result {
    char *version;
    char *clock;
    unsigned is_fresh_instance:1;

    int nr;
    struct watchman_stat *stats;
};

struct watchman_watch_list {
    int nr;
    char **roots;
};

struct watchman_pathspec {
    int depth;
    char *path;
};

struct watchman_query {
    unsigned since_is_str:1;
    unsigned all:1;
    unsigned empty_on_fresh:1;
    union {
        char *str;
        time_t time;
    } s;
    int nr_suffixes;
    int cap_suffixes;
    char **suffixes;
    int nr_paths;
    int cap_paths;
    struct watchman_pathspec *paths;
    int fields;

    /* negative for unset */
    int64_t sync_timeout;
};

struct watchman_expression {
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

struct watchman_connection *
watchman_connect(struct watchman_error *error);
int
watchman_watch(struct watchman_connection *connection, const char *path,
               struct watchman_error *error);
int
watchman_watch_del(struct watchman_connection *connection, const char *path,
                   struct watchman_error *error);
struct watchman_watch_list *
watchman_watch_list(struct watchman_connection *connection,
                    struct watchman_error *error);
struct watchman_expression *
watchman_since_expression(const char *since, enum watchman_clockspec spec);
struct watchman_expression *
watchman_since_expression_time_t(time_t time, enum watchman_clockspec spec);
struct watchman_expression *
watchman_not_expression(struct watchman_expression *expression);
struct watchman_expression *
watchman_allof_expression(int nr, struct watchman_expression **expressions);
struct watchman_expression *
watchman_anyof_expression(int nr, struct watchman_expression **expressions);
struct watchman_expression *
watchman_empty_expression(void);
struct watchman_expression *
watchman_true_expression(void);
struct watchman_expression *
watchman_false_expression(void);
struct watchman_expression *
watchman_exists_expression(void);
struct watchman_expression *
watchman_suffix_expression(const char *suffix);
struct watchman_expression *
watchman_match_expression(const char *match, enum watchman_basename basename);
struct watchman_expression *
watchman_imatch_expression(const char *match, enum watchman_basename basename);
struct watchman_expression *
watchman_pcre_expression(const char *match, enum watchman_basename basename);
struct watchman_expression *
watchman_ipcre_expression(const char *match, enum watchman_basename basename);
struct watchman_expression *
watchman_name_expression(const char *match, enum watchman_basename basename);
struct watchman_expression *
watchman_iname_expression(const char *match, enum watchman_basename basename);
struct watchman_expression *
watchman_names_expression(int nr, char const **match,
                          enum watchman_basename basename);
struct watchman_expression *
watchman_inames_expression(int nr, char const **match,
                           enum watchman_basename basename);
struct watchman_expression *
watchman_type_expression(char c);
struct watchman_query_result *
watchman_do_query(struct watchman_connection *connection, const char *fs_path,
                  const struct watchman_query *query,
                  const struct watchman_expression *expr,
                  struct watchman_error *error);
struct watchman_query *
watchman_query(void);
void
watchman_query_add_suffix(struct watchman_query *query, char *suffix);
void
watchman_query_add_path(struct watchman_query *query, char *path, int depth);
void
watchman_query_set_since_oclock(struct watchman_query *query, char *since);
void
watchman_query_set_since_time_t(struct watchman_query *query, time_t since);
void
watchman_query_set_fields(struct watchman_query *query, int fields);
void
watchman_query_set_empty_on_fresh(struct watchman_query *query,
				  bool empty_on_fresh);
void
watchman_free_expression(struct watchman_expression *expr);
void
watchman_free_query_result(struct watchman_query_result *res);
void
watchman_free_query(struct watchman_query *query);
void
watchman_free_watch_list(struct watchman_watch_list *list);
void
watchman_release_error(struct watchman_error *error);
void
watchman_connection_close(struct watchman_connection *connection);

#endif                          /* LIBWATCHMAN_WATCHMAN_H */
