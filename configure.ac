AC_INIT([cvechecker], [4.0], [sven.vermeulen@siphos.be])
AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([subdir-objects foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h],,[AC_MSG_ERROR([stdlib.h header missing])])
AC_CHECK_HEADERS([string.h],,[AC_MSG_ERROR([string.h header missing])])
AC_CHECK_HEADERS([unistd.h],,[AC_MSG_ERROR([unistd.h header missing])])

# Checks for library functions.
AC_CHECK_FUNCS([gethostname memset regcomp strchr strrchr strstr])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for dependencies.
AC_MSG_WARN([Please make sure pkg-config is installed and autoreconf run])

# libbsd is obligatory on systems where strlcpy is not in libc.
# https://man.openbsd.org/strlcpy.3
# https://libbsd.freedesktop.org/wiki/
AC_CHECK_FUNC([strlcpy],, [LIBBSD_NEEDED=yes])
AS_IF([test "x$LIBBSD_NEEDED" = "xyes"], [
  PKG_CHECK_MODULES([LIBBSD], [libbsd-overlay])
])

PKG_CHECK_MODULES([CONFIG], [libconfig >= 1.3])

# The BSD systems don't have packages in the default include/library
# paths. Let our pkg-config dependencies add those paths for us BEFORE we look
# for argp.
CFLAGS="$CFLAGS $CONFIG_CFLAGS $LIBBSD_CFLAGS"
LIBS="$LIBS $CONFIG_LIBS $LIBBSD_LIBS"

# argp-standalone is obligatory on systems where argp is not in libc.
# https://www.gnu.org/software/libc/manual/html_node/Argp.html
# https://github.com/argp-standalone/argp-standalone
AC_SEARCH_LIBS([argp_parse], [argp],,
  [AC_MSG_ERROR([argp-standalone dependency missing])]
)

## --with configs
# mysql
AC_ARG_ENABLE(mysql, [  --enable-mysql	Enable MySQL support])
if test "$enable_mysql" == "yes"; then
  PKG_CHECK_MODULES([MYSQL], [mysqlclient]);
  MYSQL_LIBS=$(mysql_config --libs)
  LIBS="$LIBS $MYSQL_LIBS";
fi
AM_CONDITIONAL([USE_MYSQL], [ test "x$enable_mysql" = "xyes" ])

AC_ARG_ENABLE(sqlite3, [  --enable-sqlite3	Enable SQLite3 support (default)])
if test "$enable_sqlite3" != "no"; then
  PKG_CHECK_MODULES([SQLITE3], [sqlite3 >= 3.6.16]);
  CFLAGS="$CFLAGS $SQLITE3_CFLAGS"
  LIBS="$LIBS $SQLITE3_LIBS";
fi
AM_CONDITIONAL([USE_SQLITE], [ test "x$enable_sqlite3" = "xyes" ])

AC_CONFIG_FILES([Makefile
		src/Makefile
		data/Makefile
		conf/Makefile
		scripts/Makefile
		docs/Makefile])
AC_OUTPUT
