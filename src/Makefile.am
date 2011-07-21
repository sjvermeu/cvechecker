# Program to build
bin_PROGRAMS = cvechecker

if USE_SQLITE
  SQLITESOURCE = sqlite3/sqlite3_impl.c sqlite3/sqlite3_impl.h
  SQLITEINCLUDE = -D_USE_SQLITE3
else
  SQLITESOURCE = dummy/dummy_sqlite3.c dummy/dummy_sqlite3.h
endif

if USE_MYSQL
  MYSQLSOURCE = mysql/mysql_impl.c mysql/mysql_impl.h
  MYSQLINCLUDE = -D_USE_MYSQL
else
  MYSQLSOURCE = dummy/dummy_mysql.c dummy/dummy_mysql.h
endif

cvechecker_SOURCES = cvecheck.h cvecheck.c swstring.h swstring.c cvecheck_common.h \
                     output/stringscmd.h output/stringscmd.c $(SQLITESOURCE) $(MYSQLSOURCE)


INCLUDES = $(SQLITEINCLUDE) $(MYSQLINCLUDE)
