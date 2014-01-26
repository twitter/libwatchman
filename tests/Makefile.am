## Process this file with automake to produce Makefile.in

TESTS = check_watchman
check_PROGRAMS = check_watchman
check_watchman_SOURCES = check_watchman.c $(top_builddir)/watchman.h
check_watchman_CFLAGS = @CHECK_CFLAGS@
check_watchman_LDADD = -L$(top_builddir)/.libs/ -lwatchman @CHECK_LIBS@
