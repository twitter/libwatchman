#include "watchman.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <jansson.h>

#include "bser_write.h"
#include "proto.h"

static int use_bser_encoding = 0;

/* It's safe to have a small buffer here because watchman's socket name
 * is guaranteed to be under 108 bytes (see sockaddr_un).  The JSON only has
 * sockname and version fields.
*/
#define WATCHMAN_GET_SOCKNAME_MAX 1024

static void watchman_err(struct watchman_error *error,
                         enum watchman_error_code code,
                         const char *message, ...)
    __attribute__ ((format(printf, 3, 4)));

static void
watchman_err(struct watchman_error *error, enum watchman_error_code code,
             const char *message, ...)
{
    if (!error)
        return;
    va_list argptr;
    va_start(argptr, message);
    char c;
    int len = vsnprintf(&c, 1, message, argptr);
    va_end(argptr);

    error->message = malloc(len + 1);
    error->code = code;
    error->err_no = errno;
    va_start(argptr, message);
    vsnprintf(error->message, len + 1, message, argptr);
    va_end(argptr);
}

static int unix_stream_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    return fd;
}

static int chdir_len(const char *orig, int len)
{
    char *path = malloc(len + 1);
    memcpy(path, orig, len);
    path[len] = 0;
    int r = chdir(path);
    free(path);
    return r;
}

struct unix_sockaddr_context {
    char *orig_dir;
};

static char *getcwd_alloc(void)
{
    int buflen = PATH_MAX;
    char *buf = NULL;

    while (1) {
        buf = realloc(buf, buflen);
        if (getcwd(buf, buflen)) {
            break;
        }

        if (errno != ERANGE) {
            return NULL;
        }
        buflen *= 2;
    }

    return buf;
}

static int unix_sockaddr_init(struct sockaddr_un *sa, const char *path,
                              struct unix_sockaddr_context *ctx)
{
    size_t size = strlen(path) + 1;

    ctx->orig_dir = NULL;
    if (size > sizeof(sa->sun_path)) {
        const char *slash = strrchr(path, '/');
        const char *dir;

        if (!slash) {
            errno = ENAMETOOLONG;
            return -1;
        }

        dir = path;
        path = slash + 1;
        size = strlen(path) + 1;
        if (size > sizeof(sa->sun_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        char *cwd = getcwd_alloc();
        if (!cwd) {
            return -1;
        }
        ctx->orig_dir = cwd;
        if (chdir_len(dir, slash - dir) < 0) {
            free(cwd);
            return -1;
        }
    }

    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    memcpy(sa->sun_path, path, size);
    return 0;
}

static int unix_sockaddr_cleanup(struct unix_sockaddr_context *ctx, struct watchman_error *error)
{
    int ret = 0;
    if (!ctx->orig_dir) {
        return 0;
    }
    /*
     * If we fail, we have moved the cwd of the whole process, which
     * could confuse calling code.  But we don't want to just die, because
     * libraries shouldn't do that.  So we'll return an error but be
     * sad about it.
     */
    if (chdir(ctx->orig_dir) < 0) {
        watchman_err(error, WATCHMAN_ERR_CWD,
                     "unable to restore original working directory");
        ret = -1;
    }
    free(ctx->orig_dir);
    return ret;
}

static int unix_stream_connect(const char *path, struct watchman_error *error)
{
    struct sockaddr_un sa;
    struct unix_sockaddr_context ctx;

    if (unix_sockaddr_init(&sa, path, &ctx) < 0) {
        return -1;
    }
    int fd = unix_stream_socket();
    if (fd < 0) {
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        watchman_err(error, WATCHMAN_ERR_CONNECT, "Connect error %s",
                     strerror(errno));

        if (unix_sockaddr_cleanup(&ctx, error)) {
            error->code |= WATCHMAN_ERR_CWD;
        }
        close(fd);
        return -1;
    }
    if (unix_sockaddr_cleanup(&ctx, error)) {
        close(fd);
        return -1;
    }
    return fd;
}

static struct watchman_connection *
watchman_sock_connect(const char *sockname, struct timeval timeout, struct watchman_error *error)
{
    use_bser_encoding = getenv("LIBWATCHMAN_USE_JSON_PROTOCOL") == NULL;
        if (getenv("LIBWATCHMAN_TRACE_WATCHMAN") != NULL) {
            fprintf(stderr, "Using bser encoding: %s\n", use_bser_encoding ? "yes" : "no");
    }

    int fd;

    error->message = NULL;
    fd = unix_stream_connect(sockname, error);
    if (fd < 0 && !error->message) {
        watchman_err(error, WATCHMAN_ERR_CONNECT, "Connect error %s",
                     strerror(errno));
        return NULL;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
        watchman_err(error, WATCHMAN_ERR_CONNECT, "Failed to set timeout %s",
                     strerror(errno));
        return NULL;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
        watchman_err(error, WATCHMAN_ERR_CONNECT, "Failed to set timeout %s",
                     strerror(errno));
        return NULL;
    }

    FILE *sockfp = fdopen(fd, "r+");
    if (!sockfp) {
        close(fd);
        watchman_err(error, WATCHMAN_ERR_OTHER,
                     "Failed to connect to watchman socket %s: %s.",
                     sockname, strerror(errno));
        return NULL;
    }
    setlinebuf(sockfp);

    struct watchman_connection *conn = malloc(sizeof(*conn));
    conn->fp = sockfp;
    return conn;
}

struct watchman_popen {
    int fd;
    int pid;
};

#define WATCHMAN_EXEC_FAILED 241
#define WATCHMAN_EXEC_INTERNAL_ERROR 242

static const char* get_sockname_msg = "Could not run watchman get-sockname: %s";
/* Runs watchman get-sockname and returns a FILE from which the output
 can be read. */
static struct watchman_popen *watchman_popen_getsockname(struct watchman_error *error)
{
    int pipefd[2];
    static struct watchman_popen ret = {0, 0};

    if (pipe(pipefd) < 0) {
        goto fail;
    }

    pid_t pid = fork();
    if (pid < 0) {
        goto fail;
    } else if (pid == 0) {
        if (dup2(pipefd[1], 1) < 0) {
            exit(WATCHMAN_EXEC_INTERNAL_ERROR);
        }

        int devnull_fh = open("/dev/null", O_RDWR);
        if (devnull_fh < 0) {
            exit(WATCHMAN_EXEC_INTERNAL_ERROR);
        }

        if (dup2(devnull_fh, 2) < 0) {
            exit(WATCHMAN_EXEC_INTERNAL_ERROR);
        }

        execlp("watchman", "watchman", "get-sockname", (char *) NULL);
        exit(WATCHMAN_EXEC_FAILED);
    } else {
        close(pipefd[1]);
        ret.fd = pipefd[0];
        ret.pid = pid;
        return &ret;
    }

fail:
    watchman_err(error, WATCHMAN_ERR_OTHER, get_sockname_msg, strerror(errno));
    return NULL;
}

int watchman_pclose(struct watchman_error *error, struct watchman_popen *popen)
{
    close(popen->fd);

    int status;
    int pid = waitpid(popen->pid, &status, 0);
    if (pid < 0) {
        watchman_err(error, WATCHMAN_ERR_RUN_WATCHMAN, get_sockname_msg,
                     strerror(errno));
        return -1;
    }

    switch(WEXITSTATUS(status)) {
    case 0:
        return 0;
    case WATCHMAN_EXEC_FAILED:
        watchman_err(error, WATCHMAN_ERR_RUN_WATCHMAN, get_sockname_msg,
                     strerror(errno));
        return -1;
    case WATCHMAN_EXEC_INTERNAL_ERROR:
        watchman_err(error, WATCHMAN_ERR_OTHER, get_sockname_msg,
                     strerror(errno));
        return -1;
    default:
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN, get_sockname_msg,
                     strerror(errno));
        return -1;
    }
}

/**
 * Calls select() on the given fd until it's ready to read from or
 * until the timeout expires. Updates timeout to indicate the
 * remaining time. Returns 1 if the socket is readable, 0 if the
 * socket is not readable, and -1 on error.
 */
static int block_on_read(int fd, struct timeval *timeout)
{
    struct timeval now, start, elapsed, orig_timeout;
    fd_set fds;
    int ret = 0;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    if (timeout != NULL) {
        gettimeofday(&start, NULL);
        memcpy(&orig_timeout, timeout, sizeof(orig_timeout));
    }

    ret = select(fd + 1, &fds, NULL, NULL, timeout);

    if (timeout != NULL) {
        gettimeofday(&now, NULL);
        timersub(&now, &start, &elapsed);
        timersub(&orig_timeout, &elapsed, timeout);
    }

    return ret;
}

/*
 * Read from fd into buf until either `bytes` bytes have been read, or
 * EOF, or the data that has been read can be parsed as JSON.  In the
 * event of a timeout or read error, returns NULL.
 */
static proto_t read_with_timeout(int fd, char* buf, size_t bytes, struct timeval timeout)
{
    size_t read_so_far = 0;
    ssize_t bytes_read = 0;

    while (read_so_far < bytes) {
        if (timeout.tv_sec || timeout.tv_usec) {
            if (timeout.tv_sec < 0 || timeout.tv_usec < 0) {
                /* Timeout */
                return proto_null();
            }

            if (1 == block_on_read(fd, &timeout)) {
                bytes_read = read(fd, buf, bytes - read_so_far);
            } else {
                return proto_null(); /* timeout or error */
            }
        } else {
            bytes_read = read(fd, buf, bytes - read_so_far);
        }
        if (bytes_read < 0) {
            return proto_null();
        }
        if (bytes_read == 0) {
            /* EOF, but we couldn't parse the JSON we have so far */
            return proto_null();
        }
        read_so_far += bytes_read;

        /* try to parse this */
        buf[read_so_far] = 0;
        proto_t proto;
        if (buf[0] <= 0x0b) {
            bser_t* bser = bser_parse_buffer((uint8_t*)buf, read_so_far, NULL);
            proto = proto_from_bser(bser);
        } else {
            json_error_t jerror;
            json_t* json = json_loads(buf, JSON_DISABLE_EOF_CHECK, &jerror);
            proto = proto_from_json(json);
        }
        return proto;
    }
    return proto_null();
}

/*
 * Connect to watchman's socket.  Sets a socket send and receive
 * timeout of `timeout`.  Pass a {0} for no-timeout.  On error,
 * returns NULL and, if `error` is non-NULL, fills it in.
 */
struct watchman_connection *
watchman_connect(struct timeval timeout, struct watchman_error *error)
{
    struct watchman_connection *conn = NULL;
    /* If an environment variable WATCHMAN_SOCK is set, establish a connection
       to that address. Otherwise, run `watchman get-sockname` to start the
       daemon and retrieve its address. */
    const char *sockname_env = getenv("WATCHMAN_SOCK");
    if (sockname_env) {
        conn = watchman_sock_connect(sockname_env, timeout, error);
        goto done;
    }
    struct watchman_popen *p = watchman_popen_getsockname(error);
    if (p == NULL) {
        return NULL;
    }

    char buf[WATCHMAN_GET_SOCKNAME_MAX + 1];

    proto_t proto = read_with_timeout(p->fd, buf, WATCHMAN_GET_SOCKNAME_MAX, timeout);

    if (watchman_pclose(error, p)) {
        goto done;
    }
    if (proto_is_null(proto)) {
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                     "Got bad or no JSON/BSER from watchman get-sockname");
        goto done;
    }
    if (!proto_is_object(proto)) {
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                     "Got bad JSON/BSER from watchman get-sockname: object expected");
        goto bad_proto;
    }
    proto_t sockname_obj = proto_object_get(proto, "sockname");
    if (proto_is_null(sockname_obj)) {
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                     "Got bad JSON/BSER from watchman get-sockname: "
                     "sockname element expected");
        goto bad_proto;
    }
    if (!proto_is_string(sockname_obj)) {
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                     "Got bad JSON/BSER from watchman get-sockname:"
                     " sockname is not string");
        goto bad_proto;
    }
    const char *sockname = proto_strdup(sockname_obj);
    conn = watchman_sock_connect(sockname, timeout, error);
bad_proto:
    proto_free(proto);
done:
    return conn;
}

static int
watchman_send_simple_command(struct watchman_connection *conn,
                             struct watchman_error *error, ...)
{
    int result = 0;
    json_t *cmd_array = json_array();
    va_list argptr;
    va_start(argptr, error);
    char *arg;
    while ((arg = va_arg(argptr, char *))) {
        json_array_append_new(cmd_array, json_string(arg));
    }
    if (use_bser_encoding) {
        result = bser_write_to_file(cmd_array, conn->fp) == 0;
    } else {
        result = json_dumpf(cmd_array, conn->fp, JSON_COMPACT);
        fputc('\n', conn->fp);
    }
    if (result) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            watchman_err(error, WATCHMAN_ERR_TIMEOUT,
                         "Timeout sending simple watchman command");
        } else {
            watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                         "Failed to send simple watchman command");
        }
        result = 1;
    }

    json_decref(cmd_array);
    return result;
}

static proto_t
watchman_read_with_timeout(struct watchman_connection *conn, struct timeval *timeout, struct watchman_error *error)
{
    proto_t result;
    json_error_t jerror;

    int ret = 1;

    if (!timeout || timeout->tv_sec || timeout->tv_usec)
        ret = block_on_read(fileno(conn->fp), timeout);
    if (ret == -1) {
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                     "Error encountered blocking on watchman");
        return proto_null();
    }

    if (ret != 1) {
        watchman_err(error, WATCHMAN_ERR_TIMEOUT,
                     "timed out waiting for watchman");
        return proto_null();
    }

    if (use_bser_encoding) {
        bser_t* bser = bser_parse_from_file(conn->fp, NULL);
        result = proto_from_bser(bser);
    } else {
        json_t* json = json_loadf(conn->fp, JSON_DISABLE_EOF_CHECK, &jerror);
        result = proto_from_json(json);
        if (fgetc(conn->fp) != '\n') {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                watchman_err(error, WATCHMAN_ERR_TIMEOUT,
                             "Timeout reading EOL from watchman");
            } else {
                watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                             "No newline at end of reply");
            }
            json_decref(json);
            return proto_null();
        }
    }
    if (proto_is_null(result)) {
        if (errno == EAGAIN) {
            watchman_err(error, WATCHMAN_ERR_TIMEOUT,
                         "Timeout:EAGAIN reading from watchman.");
        }
        else if (errno == EWOULDBLOCK) {
            watchman_err(error, WATCHMAN_ERR_TIMEOUT,
                         "Timeout:EWOULDBLOCK reading from watchman");
        } else {
            watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                         "Can't parse result from watchman: %s",
                         jerror.text);
        }
        return proto_null();
    }
    return result;
}

static proto_t
watchman_read(struct watchman_connection *conn, struct watchman_error *error)
{
  return watchman_read_with_timeout(conn, NULL, error);
}

static int
watchman_read_and_handle_errors(struct watchman_connection *conn,
                                struct watchman_error *error)
{
    proto_t obj = watchman_read(conn, error);
    if (proto_is_null(obj)) {
        return 1;
    }
    if (!proto_is_object(obj)) {
        char *bogus_text = proto_dumps(obj, 0);
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN,
                     "Got non-object result from watchman : %s",
                     bogus_text);
        free(bogus_text);
        proto_free(obj);
        return 1;
    }
    proto_t error_node = proto_object_get(obj, "error");
    if (!proto_is_null(error_node)) {
        watchman_err(error, WATCHMAN_ERR_OTHER,
                     "Got error result from watchman : %s",
                     proto_strdup(error_node));
        proto_free(obj);
        return 1;
    }

    proto_free(obj);
    return 0;
}

int
watchman_watch(struct watchman_connection *conn,
               const char *path, struct watchman_error *error)
{
    if (watchman_send_simple_command(conn, error, "watch", path, NULL)) {
        return 1;
    }
    if (watchman_read_and_handle_errors(conn, error)) {
        return 1;
    }
    return 0;
}

int
watchman_recrawl(struct watchman_connection *conn,
               const char *path, struct watchman_error *error)
{
    if (watchman_send_simple_command(conn, error, "debug-recrawl", path, NULL)) {
        return 1;
    }
    if (watchman_read_and_handle_errors(conn, error)) {
        return 1;
    }
    return 0;
}

int
watchman_watch_del(struct watchman_connection *conn,
                   const char *path, struct watchman_error *error)
{
    if (watchman_send_simple_command(conn, error, "watch-del", path, NULL)) {
        return 1;
    }
    if (watchman_read_and_handle_errors(conn, error)) {
        return 1;
    }
    return 0;
}

static struct watchman_expression *
alloc_expr(enum watchman_expression_type ty)
{
    struct watchman_expression *expr;
    expr = calloc(1, sizeof(*expr));
    expr->ty = ty;
    return expr;
}

struct watchman_expression *
watchman_since_expression(const char *since, enum watchman_clockspec spec)
{
    assert(since);
    struct watchman_expression *expr = alloc_expr(WATCHMAN_EXPR_TY_SINCE);
    expr->e.since_expr.is_str = 1;
    expr->e.since_expr.t.since = strdup(since);
    expr->e.since_expr.clockspec = spec;
    return expr;
}

struct watchman_expression *
watchman_since_expression_time_t(time_t time, enum watchman_clockspec
                                 spec)
{
    struct watchman_expression *expr = alloc_expr(WATCHMAN_EXPR_TY_SINCE);
    expr->e.since_expr.is_str = 0;
    expr->e.since_expr.t.time = time;
    expr->e.since_expr.clockspec = spec;
    return expr;
}

/* corresponds to enum watchman_expression_type */
static char *ty_str[] = {
    "allof",
    "anyof",
    "not",
    "true",
    "false",
    "since",
    "suffix",
    "match",
    "imatch",
    "pcre",
    "ipcre",
    "name",
    "iname",
    "type",
    "empty",
    "exists"
};

/* corresponds to enum watchman_clockspec */
static char *clockspec_str[] = {
    NULL,
    "oclock",
    "cclock",
    "mtime",
    "ctime"
};

/* corresponds to enum watchman_basename */
static char *basename_str[] = {
    NULL,
    "basename",
    "wholename"
};

static json_t *
json_string_from_char(char c)
{
    char str[2] = { c, 0 };
    return json_string(str);
}

static json_t *
json_string_or_array(int nr, char **items)
{
    if (nr == 1) {
        return json_string(items[0]);
    }
    json_t *result = json_array();
    int i;
    for (i = 0; i < nr; ++i) {
        json_array_append_new(result, json_string(items[i]));
    }
    return result;
}

static void
since_to_json(json_t *result, const struct watchman_expression *expr)
{
    if (expr->e.since_expr.is_str) {
        json_array_append_new(result, json_string(expr->e.since_expr.t.since));
    } else {
        json_array_append_new(result, json_integer(expr->e.since_expr.t.time));
    }
    if (expr->e.since_expr.clockspec) {
        char *clockspec = clockspec_str[expr->e.since_expr.clockspec];
        json_array_append_new(result, json_string(clockspec));
    }
}

static json_t *
to_json(const struct watchman_expression *expr)
{
    json_t *result = json_array();
    json_t *arg;
    json_array_append_new(result, json_string(ty_str[expr->ty]));

    int i;
    switch (expr->ty) {
        case WATCHMAN_EXPR_TY_ALLOF:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_ANYOF:
            for (i = 0; i < expr->e.union_expr.nr; ++i) {
                json_array_append_new(result,
                                      to_json(expr->e.union_expr.clauses[i]));
            }
            break;
        case WATCHMAN_EXPR_TY_NOT:
            json_array_append_new(result, to_json(expr->e.not_expr.clause));
            break;
        case WATCHMAN_EXPR_TY_TRUE:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_FALSE:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_EMPTY:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_EXISTS:
            /* Nothing to do */
            break;

        case WATCHMAN_EXPR_TY_SINCE:
            since_to_json(result, expr);
            break;
        case WATCHMAN_EXPR_TY_SUFFIX:
            json_array_append_new(result,
                                  json_string(expr->e.suffix_expr.suffix));
            break;
        case WATCHMAN_EXPR_TY_MATCH:
                                   /*-fallthrough*/
        case WATCHMAN_EXPR_TY_IMATCH:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_PCRE:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_IPCRE:
            json_array_append_new(result,
                                  json_string(expr->e.match_expr.match));
            if (expr->e.match_expr.basename) {
                char *base = basename_str[expr->e.match_expr.basename];
                json_array_append_new(result, json_string(base));
            }
            break;
        case WATCHMAN_EXPR_TY_NAME:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_INAME:
            arg =
                json_string_or_array(expr->e.name_expr.nr,
                                     expr->e.name_expr.names);
            json_array_append_new(result, arg);
            if (expr->e.name_expr.basename) {
                char *base = basename_str[expr->e.name_expr.basename];
                json_array_append_new(result, json_string(base));
            }
            break;
        case WATCHMAN_EXPR_TY_TYPE:
            json_array_append_new(result,
                                  json_string_from_char(expr->e.
                                                        type_expr.type));
    }
    return result;
}

/* corresponds to enum watchman_fields */
static char *fields_str[] = {
    "name",
    "exists",
    "cclock",
    "oclock",
    "ctime",
    "ctime_ms",
    "ctime_us",
    "ctime_ns",
    "ctime_f",
    "mtime",
    "mtime_ms",
    "mtime_us",
    "mtime_ns",
    "mtime_f",
    "size",
    "uid",
    "gid",
    "ino",
    "dev",
    "nlink",
    "new",
    "mode"
};

json_t *
fields_to_json(int fields)
{
    json_t *result = json_array();
    int i = 0;
    int mask;
    for (mask = 1; mask < WATCHMAN_FIELD_END; mask *= 2) {
        if (fields & mask) {
            json_array_append_new(result, json_string(fields_str[i]));
        }
        ++i;
    }
    return result;
}

#define PROTO_ASSERT(cond, condarg, msg)                                \
    if (!cond(condarg)) {                                               \
        char *dump = proto_dumps(condarg, 0);                           \
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_BROKEN, msg, dump);   \
        free(dump);                                                     \
        goto done;                                                      \
    }

struct watchman_watch_list *
watchman_watch_list(struct watchman_connection *conn,
                    struct watchman_error *error)
{
    struct watchman_watch_list *res = NULL;
    struct watchman_watch_list *result = NULL;
    if (watchman_send_simple_command(conn, error, "watch-list", NULL)) {
        return NULL;
    }

    proto_t obj = watchman_read(conn, error);
    if (proto_is_null(obj)) {
        return NULL;
    }
    PROTO_ASSERT(proto_is_object, obj, "Got bogus value from watch-list %s");
    proto_t roots = proto_object_get(obj, "roots");
    PROTO_ASSERT(proto_is_array, roots, "Got bogus value from watch-list %s");

    res = malloc(sizeof(*res));
    int nr = proto_array_size(roots);
    res->nr = 0;
    res->roots = calloc(nr, sizeof(*res->roots));
    int i;
    for (i = 0; i < nr; ++i) {
        proto_t root = proto_array_get(roots, i);
        PROTO_ASSERT(proto_is_string, root,
                    "Got non-string root from watch-list %s");
        res->nr++;
        res->roots[i] = proto_strdup(root);
    }
    result = res;
    res = NULL;
done:
    if (res) {
        watchman_free_watch_list(res);
    }
    proto_free(obj);
    return result;
}

#define WRITE_BOOL_STAT(stat, statobj, attr)                               \
    proto_t attr = proto_object_get(statobj, #attr);                       \
    if (!proto_is_null(attr)) {                                            \
        PROTO_ASSERT(proto_is_boolean, attr, #attr " is not boolean: %s"); \
        stat->attr = proto_is_true(attr);                                  \
    }

#define WRITE_INT_STAT(stat, statobj, attr)                               \
    proto_t attr = proto_object_get(statobj, #attr);                      \
    if (!proto_is_null(attr)) {                                           \
        PROTO_ASSERT(proto_is_integer, attr, #attr " is not an int: %s"); \
        stat->attr = proto_integer_value(attr);                           \
    }

#define WRITE_STR_STAT(stat, statobj, attr)                                \
    proto_t attr = proto_object_get(statobj, #attr);                       \
    if (!proto_is_null(attr)) {                                            \
        PROTO_ASSERT(proto_is_string, attr, #attr " is not a string: %s"); \
        stat->attr = proto_strdup(attr);                                   \
    }

#define WRITE_FLOAT_STAT(stat, statobj, attr)                           \
    proto_t attr = proto_object_get(statobj, #attr);                    \
    if (!proto_is_null(attr)) {                                         \
        PROTO_ASSERT(proto_is_real, attr, #attr " is not a float: %s"); \
        stat->attr = proto_real_value(attr);                            \
    }

static int
watchman_send(struct watchman_connection *conn,
              json_t *query, struct watchman_error *error)
{
    int result;
    if (use_bser_encoding) {
        result = bser_write_to_file(query, conn->fp) == 0;
    } else {
        result = json_dumpf(query, conn->fp, JSON_COMPACT);
        fputc('\n', conn->fp);
    }
    if (result) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            watchman_err(error, WATCHMAN_ERR_TIMEOUT,
                         "Timeout sending to watchman");
        } else {
            char *dump = json_dumps(query, 0);
            watchman_err(error, WATCHMAN_ERR_OTHER,
                     "Failed to send watchman query %s", dump);
            free(dump);
        }
        return 1;
    }
    return 0;
}

char *
watchman_clock(struct watchman_connection *conn,
               const char *path,
               unsigned int sync_timeout,
               struct watchman_error *error)
{
    char *result = NULL;
    json_t *query = json_array();
    json_array_append_new(query, json_string("clock"));
    json_array_append_new(query, json_string(path));
    if (sync_timeout) {
        json_t *options = json_object();
        json_object_set_new(options, "sync_timeout", json_integer(sync_timeout));
        json_array_append_new(query, options);
    }

    int ret = watchman_send(conn, query, error);
    json_decref(query);
    if (ret) {
        return NULL;
    }

    proto_t obj = watchman_read(conn, error);
    if (proto_is_null(obj)) {
        return NULL;
    }
    PROTO_ASSERT(proto_is_object, obj, "Got bogus value from clock %s");
    proto_t clock = proto_object_get(obj, "clock");
    PROTO_ASSERT(proto_is_string, clock, "Bad clock %s");
    result = proto_strdup(clock);

done:
    proto_free(obj);
    return result;
}

static struct watchman_query_result *
watchman_query_json(struct watchman_connection *conn,
                    json_t *query,
                    struct timeval *timeout,
                    struct watchman_error *error)
{
    struct watchman_query_result *result = NULL;
    struct watchman_query_result *res = NULL;

    if (watchman_send(conn, query, error)) {
        return NULL;
    }
    /* parse the result */
    proto_t obj = watchman_read_with_timeout(conn, timeout, error);
    if (proto_is_null(obj)) {
        return NULL;
    }
    PROTO_ASSERT(proto_is_object, obj, "Failed to send watchman query %s");

    proto_t jerror = proto_object_get(obj, "error");
    if (!proto_is_null(jerror)) {
        watchman_err(error, WATCHMAN_ERR_WATCHMAN_REPORTED,
                     "Error result from watchman: %s",
                     proto_strdup(jerror));
        goto done;
    }

    res = calloc(1, sizeof(*res));

    proto_t files = proto_object_get(obj, "files");
    PROTO_ASSERT(proto_is_array, files, "Bad files %s");

    int nr = proto_array_size(files);
    res->stats = calloc(nr, sizeof(*res->stats));

    int i;
    for (i = 0; i < nr; ++i) {
        struct watchman_stat *stat = res->stats + i;
        proto_t statobj = proto_array_get(files, i);
        if (proto_is_string(statobj)) {
            /* then hopefully we only requested names */
            stat->name = proto_strdup(statobj);
            res->nr++;
            continue;
        }

        PROTO_ASSERT(proto_is_object, statobj, "must be object: %s");

        proto_t name = proto_object_get(statobj, "name");
        PROTO_ASSERT(proto_is_string, name, "name must be string: %s");
        stat->name = proto_strdup(name);

        WRITE_BOOL_STAT(stat, statobj, exists);
        WRITE_INT_STAT(stat, statobj, ctime);
        WRITE_INT_STAT(stat, statobj, ctime_ms);
        WRITE_INT_STAT(stat, statobj, ctime_us);
        WRITE_INT_STAT(stat, statobj, ctime_ns);
        WRITE_INT_STAT(stat, statobj, dev);
        WRITE_INT_STAT(stat, statobj, gid);
        WRITE_INT_STAT(stat, statobj, ino);
        WRITE_INT_STAT(stat, statobj, mode);
        WRITE_INT_STAT(stat, statobj, mtime);
        WRITE_INT_STAT(stat, statobj, mtime_ms);
        WRITE_INT_STAT(stat, statobj, mtime_us);
        WRITE_INT_STAT(stat, statobj, mtime_ns);
        WRITE_INT_STAT(stat, statobj, nlink);
        WRITE_INT_STAT(stat, statobj, size);
        WRITE_INT_STAT(stat, statobj, uid);

        WRITE_STR_STAT(stat, statobj, cclock);
        WRITE_STR_STAT(stat, statobj, oclock);

        WRITE_FLOAT_STAT(stat, statobj, ctime_f);
        WRITE_FLOAT_STAT(stat, statobj, mtime_f);

        /* the one we have to do manually because we don't
         * want to use the name "new" */
        proto_t newer = proto_object_get(statobj, "new");
        if (!proto_is_null(newer)) {
            stat->newer = proto_is_true(newer);
        }
        res->nr++;
    }

    proto_t version = proto_object_get(obj, "version");
    PROTO_ASSERT(proto_is_string, version, "Bad version %s");
    res->version = proto_strdup(version);

    proto_t clock = proto_object_get(obj, "clock");
    PROTO_ASSERT(proto_is_string, clock, "Bad clock %s");
    res->clock = proto_strdup(clock);

    proto_t fresh = proto_object_get(obj, "is_fresh_instance");
    PROTO_ASSERT(proto_is_boolean, fresh, "Bad is_fresh_instance %s");
    res->is_fresh_instance = proto_is_true(fresh);

    result = res;
    res = NULL;
done:
    if (res) {
        watchman_free_query_result(res);
    }
    proto_free(obj);
    return result;
}

struct watchman_query *
watchman_query(void)
{
    struct watchman_query *result = calloc(1, sizeof(*result));
    result->sync_timeout = -1;
    return result;
}

void
watchman_free_query(struct watchman_query *query)
{
    if (query->since_is_str) {
        free(query->s.str);
        query->s.str = NULL;
    }
    if (query->nr_suffixes) {
        int i;
        for (i = 0; i < query->nr_suffixes; ++i) {
            free(query->suffixes[i]);
            query->suffixes[i] = NULL;
        }
        free(query->suffixes);
        query->suffixes = NULL;
    }
    if (query->nr_paths) {
        int i;
        for (i = 0; i < query->nr_paths; ++i) {
            free(query->paths[i].path);
            query->paths[i].path = NULL;
        }
        free(query->paths);
        query->paths = NULL;
    }
    free(query);
}

void
watchman_query_add_suffix(struct watchman_query *query, const char *suffix)
{
    assert(suffix);
    if (query->cap_suffixes == query->nr_suffixes) {
        if (query->nr_suffixes == 0) {
            query->cap_suffixes = 10;
        } else {
            query->cap_suffixes *= 2;
        }
        int new_size = sizeof(*query->suffixes) * query->cap_suffixes;
        query->suffixes = realloc(query->suffixes, new_size);
    }
    query->suffixes[query->nr_suffixes] = strdup(suffix);
    query->nr_suffixes++;
}

void
watchman_query_add_path(struct watchman_query *query, const char *path, int depth)
{
    if (query->cap_paths == query->nr_paths) {
        if (query->nr_paths == 0) {
            query->cap_paths = 10;
        } else {
            query->cap_paths *= 2;
        }
        int new_size = sizeof(*query->paths) * query->cap_paths;
        query->paths = realloc(query->paths, new_size);
    }
    query->paths[query->nr_paths].path = strdup(path);
    query->paths[query->nr_paths].depth = depth;
    query->nr_paths++;
}

void
watchman_query_set_since_oclock(struct watchman_query *query, const char *since)
{
    if (query->since_is_str) {
        free(query->s.str);
    }
    query->since_is_str = 1;
    query->s.str = strdup(since);
}

void
watchman_query_set_since_time_t(struct watchman_query *query, time_t since)
{
    if (query->since_is_str) {
        free(query->s.str);
    }
    query->since_is_str = 1;
    query->s.time = since;
}

void
watchman_query_set_fields(struct watchman_query *query, int fields)
{
    query->fields = fields;
}

void
watchman_query_set_empty_on_fresh(struct watchman_query *query,
                                  bool empty_on_fresh)
{
    query->empty_on_fresh = empty_on_fresh;
}

static json_t *
json_path(struct watchman_pathspec *spec)
{
    if (spec->depth == -1) {
        return json_string(spec->path);
    }

    json_t *obj = json_object();
    json_object_set_new(obj, "depth", json_integer(spec->depth));
    json_object_set_new(obj, "path", json_string(spec->path));
    return obj;
}

struct watchman_query_result *
watchman_do_query_timeout(struct watchman_connection *conn,
                          const char *fs_path,
                          const struct watchman_query *query,
                          const struct watchman_expression *expr,
                          struct timeval *timeout,
                          struct watchman_error *error)
{
    /* construct the json */
    json_t *json = json_array();
    json_array_append_new(json, json_string("query"));
    json_array_append_new(json, json_string(fs_path));
    json_t *obj = json_object();
    json_object_set_new(obj, "expression", to_json(expr));
    if (query) {
        if (query->fields) {
            json_object_set_new(obj, "fields", fields_to_json(query->fields));
        }

        if (query->empty_on_fresh) {
            json_object_set_new(obj, "empty_on_fresh_instance",
                                json_true());
        }

        if (query->s.time) {
            if (query->since_is_str) {
                json_object_set_new(obj, "since", json_string(query->s.str));
            } else {
                json_t *since = json_integer(query->s.time);
                json_object_set_new(obj, "since", since);
            }
        }

        if (query->nr_suffixes) {
            /* Note that even if you have only one suffix,
             * watchman requires this to be an array. */
            int i;
            json_t *suffixes = json_array();
            for (i = 0; i < query->nr_suffixes; ++i) {
                json_array_append_new(suffixes,
                                      json_string(query->suffixes[i]));
            }
            json_object_set_new(obj, "suffix", suffixes);
        }
        if (query->nr_paths) {
            int i;
            json_t *paths = json_array();
            for (i = 0; i < query->nr_paths; ++i) {
                json_array_append_new(paths, json_path(&query->paths[i]));
            }
            json_object_set_new(obj, "path", paths);
        }

        if (query->all) {
            json_object_set_new(obj, "all", json_string("all"));
        }

        if (query->sync_timeout >= 0) {
            json_object_set_new(obj, "sync_timeout",
                                json_integer(query->sync_timeout));
        }
    }
    json_array_append_new(json, obj);

    /* do the query */
    struct watchman_query_result *r = watchman_query_json(conn, json, timeout, error);
    json_decref(json);
    return r;
}

struct watchman_query_result *
watchman_do_query(struct watchman_connection *conn,
                  const char *fs_path,
                  const struct watchman_query *query,
                  const struct watchman_expression *expr,
                  struct watchman_error *error)
{
  struct timeval unused = {0};
  return watchman_do_query_timeout(conn, fs_path, query, expr, &unused, error);
}

void
watchman_free_expression(struct watchman_expression *expr)
{
    int i;
    switch (expr->ty) {
        case WATCHMAN_EXPR_TY_ALLOF:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_ANYOF:
            for (i = 0; i < expr->e.union_expr.nr; ++i) {
                watchman_free_expression(expr->e.union_expr.clauses[i]);
            }
            free(expr->e.union_expr.clauses);
            free(expr);
            break;
        case WATCHMAN_EXPR_TY_NOT:
            watchman_free_expression(expr->e.not_expr.clause);
            free(expr);
            break;
        case WATCHMAN_EXPR_TY_TRUE:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_FALSE:
            /*-fallthrough*/
            /* These are singletons; don't delete them */
            break;
        case WATCHMAN_EXPR_TY_SINCE:
            if (expr->e.since_expr.is_str) {
                free(expr->e.since_expr.t.since);
            }
            free(expr);
            break;
        case WATCHMAN_EXPR_TY_SUFFIX:
            free(expr->e.suffix_expr.suffix);
            free(expr);
            break;
        case WATCHMAN_EXPR_TY_MATCH:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_IMATCH:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_PCRE:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_IPCRE:
            /*-fallthrough*/
            free(expr->e.match_expr.match);
            free(expr);
            break;
        case WATCHMAN_EXPR_TY_NAME:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_INAME:
            for (i = 0; i < expr->e.name_expr.nr; ++i) {
                free(expr->e.name_expr.names[i]);
            }
            free(expr->e.name_expr.names);
            free(expr);
            break;
        case WATCHMAN_EXPR_TY_TYPE:
            free(expr);
            break;
        case WATCHMAN_EXPR_TY_EMPTY:
            /*-fallthrough*/
        case WATCHMAN_EXPR_TY_EXISTS:
            /* These are singletons; don't delete them */
            break;
    }
}

void
watchman_connection_close(struct watchman_connection *conn)
{
    if (!conn->fp) {
        return;
    }
    fclose(conn->fp);
    conn->fp = NULL;
    free(conn);
}

void
watchman_release_error(struct watchman_error *error)
{
    if (error->message) {
        free(error->message);
    }
}

void
watchman_free_watch_list(struct watchman_watch_list *list)
{
    int i;
    for (i = 0; i < list->nr; ++i) {
        free(list->roots[i]);
        list->roots[i] = NULL;
    }
    free(list->roots);
    list->roots = NULL;
    free(list);
}

/* Not a _free_ function, since stats are allocated as a block. */
static void
watchman_release_stat(struct watchman_stat *stat)
{
    if (stat->name) {
        free(stat->name);
        stat->name = NULL;
    }
}

void
watchman_free_query_result(struct watchman_query_result *result)
{
    if (result->version) {
        free(result->version);
        result->version = NULL;
    }
    if (result->clock) {
        free(result->clock);
        result->clock = NULL;
    }
    if (result->stats) {
        int i;
        for (i = 0; i < result->nr; ++i) {
            watchman_release_stat(&(result->stats[i]));
        }
        free(result->stats);
        result->stats = NULL;
    }
    free(result);
}

struct watchman_expression *
watchman_not_expression(struct watchman_expression *expression)
{
    struct watchman_expression *not_expr = alloc_expr(WATCHMAN_EXPR_TY_NOT);
    not_expr->e.not_expr.clause = expression;
    return not_expr;
}

static struct watchman_expression *
watchman_union_expression(enum watchman_expression_type
                          ty, int nr, struct watchman_expression **expressions)
{
    assert(nr);
    assert(expressions);
    size_t sz = sizeof(*expressions);
    struct watchman_expression *result = malloc(sizeof(*result));
    result->ty = ty;
    result->e.union_expr.nr = nr;
    result->e.union_expr.clauses = malloc(nr * sz);
    memcpy(result->e.union_expr.clauses, expressions, nr * sz);
    return result;
}

struct watchman_expression *
watchman_allof_expression(int nr, struct watchman_expression **expressions)
{
    return watchman_union_expression(WATCHMAN_EXPR_TY_ALLOF, nr, expressions);
}

struct watchman_expression *
watchman_anyof_expression(int nr, struct watchman_expression **expressions)
{
    return watchman_union_expression(WATCHMAN_EXPR_TY_ANYOF, nr, expressions);
}

#define STATIC_EXPR(ty, tylower)                                        \
    static struct watchman_expression ty##_EXPRESSION =                 \
        { WATCHMAN_EXPR_TY_##ty };                                      \
    struct watchman_expression *                                        \
    watchman_##tylower##_expression(void)                               \
    {                                                                   \
        return &ty##_EXPRESSION;                                        \
    }

STATIC_EXPR(EMPTY, empty)
STATIC_EXPR(TRUE, true)
STATIC_EXPR(FALSE, false)
STATIC_EXPR(EXISTS, exists)
#undef STATIC_EXPR

struct watchman_expression *
watchman_suffix_expression(const char *suffix)
{
    assert(suffix);
    struct watchman_expression *expr = alloc_expr(WATCHMAN_EXPR_TY_SUFFIX);
    expr->e.suffix_expr.suffix = strdup(suffix);
    return expr;
}

#define MATCH_EXPR(tyupper, tylower)                                    \
    struct watchman_expression *                                        \
    watchman_##tylower##_expression(const char *match,                  \
                                    enum watchman_basename basename)    \
    {                                                                   \
        assert(match);                                                  \
        struct watchman_expression *expr =                              \
            alloc_expr(WATCHMAN_EXPR_TY_##tyupper);                     \
        expr->e.match_expr.match = strdup(match);                       \
        expr->e.match_expr.basename = basename;                         \
        return expr;                                                    \
    }

MATCH_EXPR(MATCH, match)
MATCH_EXPR(IMATCH, imatch)
MATCH_EXPR(PCRE, pcre)
MATCH_EXPR(IPCRE, ipcre)
#undef MATCH_EXPR

#define NAME_EXPR(tyupper, tylower)                                     \
    struct watchman_expression *                                        \
    watchman_##tylower##_expression(const char *name,                   \
                                    enum watchman_basename basename)    \
    {                                                                   \
        assert(name);                                                   \
        return watchman_##tylower##s_expression(1, &name, basename);    \
    }

NAME_EXPR(NAME, name)
NAME_EXPR(INAME, iname)
#undef NAME_EXPR

#define NAMES_EXPR(tyupper, tylower)                                    \
    struct watchman_expression *                                        \
    watchman_##tylower##s_expression(int nr, const char **names,        \
                                     enum watchman_basename basename)   \
    {                                                                   \
        assert(nr);                                                     \
        assert(names);                                                  \
        struct watchman_expression *result =                            \
            alloc_expr(WATCHMAN_EXPR_TY_##tyupper);                     \
        result->e.name_expr.nr = nr;                                    \
        result->e.name_expr.names = malloc(nr * sizeof(*names));        \
        int i;                                                          \
        for (i = 0; i < nr; ++i) {                                      \
            result->e.name_expr.names[i] = strdup(names[i]);            \
        }                                                               \
        return result;                                                  \
    }

NAMES_EXPR(NAME, name)
NAMES_EXPR(INAME, iname)
#undef NAMES_EXPR

struct watchman_expression *
watchman_type_expression(char c)
{
    struct watchman_expression *result = alloc_expr(WATCHMAN_EXPR_TY_TYPE);
    result->e.type_expr.type = c;
    return result;
}

int
watchman_version(struct watchman_connection *conn,
                 struct watchman_error *error,
                 struct watchman_version* version)
{
    const char *result = NULL;
    json_t *cmd = json_array();
    json_array_append_new(cmd, json_string("version"));

    int ret = watchman_send(conn, cmd, error);
    json_decref(cmd);
    if (ret) {
        return -1;
    }

    proto_t obj = watchman_read(conn, error);
    if (proto_is_null(obj)) {
        return -1;
    }
    PROTO_ASSERT(proto_is_object, obj, "Got bogus value from version %s");
    proto_t version_field = proto_object_get(obj, "version");
    PROTO_ASSERT(proto_is_string, version_field, "Bad version %s");
    result = proto_strdup(version_field);

    int count = sscanf(result, "%d.%d.%d", &version->major,
                       &version->minor, &version->micro);
    proto_free(obj);
    return count == 3 ? 0 : -1;

done:
    proto_free(obj);
    return -1;
}

int
watchman_shutdown_server(struct watchman_connection *conn,
                         struct watchman_error *error)
{
    json_t *cmd = json_array();
    json_array_append_new(cmd, json_string("shutdown-server"));

    int ret = watchman_send(conn, cmd, error);
    json_decref(cmd);

    if (ret) {
        return -1;
    }

    proto_t obj = watchman_read(conn, error);
    if (proto_is_null(obj)) {
        return -1;
    }

    proto_free(obj);
    return 0;
}
