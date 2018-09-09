AC_INIT([cvechecker], [3.9], [sven.vermeulen@siphos.be])
AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([subdir-objects foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

AC_MSG_CHECKING([Determining host operating system])
OSNAME=`uname -s`
AC_MSG_RESULT($OSNAME)
case "$OSNAME" in
  FreeBSD*)
    # Include the packages - needed for argp_standalone
    export CPPFLAGS="$CPPFLAGS -I/usr/local/include"
    export LDFLAGS="$LDFLAGS -L /usr/local/lib"
    AC_MSG_RESULT([FreeBSD: adding /usr/local])
    ;;
  NetBSD*)
    # Include the packages - needed for argp
    export CPPFLAGS="$CPPFLAGS -I/usr/pkg/include"
    export LDFLAGS="$LDFLAGS -L /usr/pkg/lib"
    AC_MSG_RESULT([NetBSD: adding /usr/pkg])
    ;;
esac

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h],,[AC_MSG_ERROR([stdlib.h header missing])])
AC_CHECK_HEADERS([string.h],,[AC_MSG_ERROR([string.h header missing])])
AC_CHECK_HEADERS([unistd.h],,[AC_MSG_ERROR([unistd.h header missing])])
AC_CHECK_HEADERS([argp.h],,[AC_MSG_ERROR([argp.h header missing (part of GNU coreutils)])])

# Checks for library functions.
AC_CHECK_FUNCS([gethostname memset regcomp strchr strrchr strstr])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

AC_MSG_WARN([Please make sure pkg-config is installed and autoreconf run])
PKG_CHECK_MODULES([CONFIG], [libconfig >= 1.3])
CFLAGS="$CFLAGS $CONFIG_CFLAGS"
LIBS="$LIBS $CONFIG_LIBS"
## --with configs
# mysql
AC_ARG_ENABLE(mysql, [  --enable-mysql	Enable MySQL support])
if test "$enable_mysql" == "yes"; then
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
