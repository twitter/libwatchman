AC_INIT([libwatchman], [0.0.4], [], [libwatchman])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([dist-bzip2 subdir-objects foreign])
AC_CONFIG_MACRO_DIR([m4])

CFLAGS="$CFLAGS -Wall -std=c99 -D_XOPEN_SOURCE -D_BSD_SOURCE"

AC_PROG_CC
AC_PROG_CPP
AC_PROG_LIBTOOL
AM_PROG_CC_C_O
AM_PROG_AS

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

LT_INIT()

AC_SEARCH_LIBS([socket], [socket], [], AC_MSG_ERROR([unable to find socket()]))
AC_SEARCH_LIBS([json_array], [jansson], [], AC_MSG_ERROR([unable to find jansson]))

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile tests/Makefile])
AC_OUTPUT

