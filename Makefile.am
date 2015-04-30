SUBDIRS = . tests

ACLOCAL_AMFLAGS=-I m4
libwatchman_la_SOURCES = watchman.c
libwatchman_la_LDFLAGS= -ljansson -version-info 1:0:0

lib_LTLIBRARIES = libwatchman.la

include_HEADERS = watchman.h

EXTRA_DIST = LICENSE
