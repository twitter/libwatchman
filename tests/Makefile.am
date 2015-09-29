## Process this file with automake to produce Makefile.in

TESTS = check_watchman
check_PROGRAMS = check_watchman
noinst_PROGRAMS = json2bser bser2json

check_watchman_SOURCES = check_watchman.c $(top_builddir)/watchman.h
check_watchman_CFLAGS = -g @CHECK_CFLAGS@
check_watchman_LDADD = ../libwatchman.la @CHECK_LIBS@
check_watchman_LDFLAGS = -Wl,-rpath -Wl,$(prefix)

json2bser_SOURCES = json2bser.c $(top_builddir)/bser.h
json2bser_LDADD = ../libwatchman.la
json2bser_LDFLAGS = -Wl,-rpath -Wl,$(prefix)

bser2json_SOURCES = bser2json.c $(top_builddir)/bser.h
bser2json_LDADD = ../libwatchman.la
bser2json_LDFLAGS = -Wl,-rpath -Wl,$(prefix)
