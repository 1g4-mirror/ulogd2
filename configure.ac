dnl Process this file with autoconf to produce a configure script.
AC_INIT([ulogd], [2.0.9])
AC_PREREQ([2.50])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign tar-pax no-dist-gzip dist-xz 1.10b subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Checks for programs.
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT([disable-static])

dnl Checks for libraries.
AC_SEARCH_LIBS([dlopen], [dl], [libdl_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libdl_LIBS])

dnl Checks for header files.
AC_HEADER_DIRENT
AC_CHECK_HEADERS([fcntl.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_SYS_LARGEFILE

dnl Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([socket strerror])

AC_SEARCH_LIBS([pthread_create], [pthread], [libpthread_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libpthread_LIBS])

dnl Check for the right nfnetlink version
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 1.0.2])

AC_ARG_ENABLE([nflog],
              [AS_HELP_STRING([--enable-nflog], [Enable nflog module [default=yes]])],
              [enable_nflog=$enableval],
              [enable_nflog=yes])
AS_IF([test "x$enable_nflog" = "xyes"],
      [PKG_CHECK_MODULES([LIBNETFILTER_LOG], [libnetfilter_log >= 1.0.2])
       AC_DEFINE([BUILD_NFLOG], [1], [Building nflog module])],
      [enable_nflog=no])
AM_CONDITIONAL([BUILD_NFLOG], [test "x$enable_nflog" = "xyes"])

AC_ARG_ENABLE([nfct],
              [AS_HELP_STRING([--enable-nfct], [Enable nfct module [default=yes]])],
              [enable_nfct=$enableval],
              [enable_nfct=yes])
AS_IF([test "x$enable_nfct" = "xyes"],
      [PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.1.0])
       AC_DEFINE([BUILD_NFCT], [1], [Building nfct module])],
      [enable_nfct=no])
AM_CONDITIONAL([BUILD_NFCT], [test "x$enable_nfct" = "xyes"])

AC_ARG_ENABLE([nfacct],
              [AS_HELP_STRING([--enable-nfacct], [Enable nfacct module [default=yes]])],
              [enable_nfacct=$enableval],
              [enable_nfacct=yes])
AS_IF([test "x$enable_nfacct" = "xyes"],
      [PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.5])
       PKG_CHECK_MODULES([LIBNETFILTER_ACCT], [libnetfilter_acct >= 1.0.3])
       AC_DEFINE([BUILD_NFACCT], [1], [Building nfacct module])],
      [enable_nfacct=no])
AM_CONDITIONAL([BUILD_NFACCT], [test "x$enable_nfacct" = "xyes"])

AC_ARG_ENABLE([pgsql],
              [AS_HELP_STRING([--enable-pgsql], [Enable PostgreSQL output plugin [default=test]])])
AS_IF([test "x$enable_pgsql" != "xno"], [

  PKG_CHECK_EXISTS([libpq], [PKG_CHECK_MODULES([libpq], [libpq])], [

    AC_ARG_WITH([pg_config],
                [AS_HELP_STRING([--with-pg-config=PATH], [Path to the pg_config script])],
                [pg_config="$withval"], [pg_config=pg_config])

    AC_MSG_CHECKING([for pg_config])

    AS_IF([command -v "$pg_config" >/dev/null], [

      libpq_CFLAGS="-I`$pg_config --includedir`"
      libpq_LIBS="`$pg_config --libdir` -lpq"

      AC_SUBST([libpq_CFLAGS])
      AC_SUBST([libpq_LIBS])

      AC_MSG_RESULT([$pg_config])

    ], [
      AC_MSG_RESULT([no])
    ])

    AS_IF([test "x$libpq_LIBS" = "x"], [
      AS_IF([test "x$enable_pgsql" = "xyes"], [
        AC_MSG_ERROR([libpq not found])
      ])
    ])

  ])

])
AS_IF([test "x$libpq_LIBS" != "x"], [enable_pgsql=yes], [enable_pgsql=no])
AM_CONDITIONAL([HAVE_PGSQL], [test "x$libpq_LIBS" != "x"])

AC_ARG_ENABLE([mysql],
              [AS_HELP_STRING([--enable-mysql], [Enable MySQL output plugin [default=test]])])
AS_IF([test "x$enable_mysql" != "xno"], [

  PKG_CHECK_EXISTS([mysqlclient],
                   [PKG_CHECK_MODULES([libmysqlclient], [mysqlclient])],
                   [

    AC_ARG_WITH([mysql-config],
                [AS_HELP_STRING([--with-mysql-config=PATH], [Path to the mysql_config script])],
                [mysql_config="$withval"], [mysql_config=mysql_config])

    AC_MSG_CHECKING([for mysql_config])

    AS_IF([command -v "$mysql_config" >/dev/null], [

      MYSQL_CLIENT_CFLAGS=`$mysql_config --cflags`
      MYSQL_CLIENT_LIBS=`$mysql_config --libs`

      AC_SUBST([MYSQL_CLIENT_CFLAGS])
      AC_SUBST([MYSQL_CLIENT_LIBS])

      AC_MSG_RESULT([$mysql_config])

      dnl Some distro's don't put mysql_config in the same package as the
      dnl headers and .so sym-links.  Therefore, it is possible that the former
      dnl may be available, but the latter may not.  Hence, we check explicitly
      dnl for mysql.h.

      ulogd_save_CPPFLAGS="$CPPFLAGS"
      CPPFLAGS="$MYSQL_CLIENT_CFLAGS"
      AC_CHECK_HEADER([mysql.h], [

        libmysqlclient_CFLAGS="$MYSQL_CLIENT_CFLAGS"
        libmysqlclient_LIBS="$MYSQL_CLIENT_LIBS"

        AC_SUBST([libmysqlclient_CFLAGS])
        AC_SUBST([libmysqlclient_LIBS])

      ])
      CPPFLAGS="$ulogd_save_CPPFLAGS"

    ], [
      AC_MSG_RESULT([no])
    ])

    AS_IF([test "x$libmysqlclient_LIBS" = "x"], [
      AS_IF([test "x$enable_mysql" = "xyes"], [
        AC_MSG_ERROR([libmysqlclient not found])
      ])
    ])

  ])

])
AS_IF([test "x$libmysqlclient_LIBS" != "x"], [enable_mysql=yes], [enable_mysql=no])
AM_CONDITIONAL([HAVE_MYSQL], [test "x$libmysqlclient_LIBS" != "x"])

AC_ARG_ENABLE([sqlite3],
              [AS_HELP_STRING([--enable-sqlite3], [Enable SQLITE3 output plugin [default=test]])])
AS_IF([test "x$enable_sqlite3" != "xno"], [
  PKG_CHECK_MODULES([libsqlite3], [sqlite3], [], [
    AS_IF([test "x$enable_sqlite3" = "xyes"], [
      AC_MSG_ERROR([$libsqlite3_PKG_ERRORS])
    ])
  ])
])
AS_IF([test "x$libsqlite3_LIBS" != "x"], [enable_sqlite3=yes], [enable_sqlite3=no])
AM_CONDITIONAL([HAVE_SQLITE3], [test "x$libsqlite3_LIBS" != "x"])

AC_ARG_ENABLE([dbi],
              [AS_HELP_STRING([--enable-dbi], [Enable DBI output plugin [default=test]])])
AS_IF([test "x$enable_dbi" != "xno"], [
  PKG_CHECK_MODULES([libdbi], [dbi], [], [
    AS_IF([test "x$enable_dbi" = "xyes"], [
      AC_MSG_ERROR([$libdbi_PKG_ERRORS])
    ])
  ])
])
AS_IF([test "x$libdbi_LIBS" != "x"], [enable_dbi=yes], [enable_dbi=no])
AM_CONDITIONAL([HAVE_DBI], [test "x$libdbi_LIBS" != "x"])

AC_ARG_ENABLE([pcap],
              [AS_HELP_STRING([--enable-pcap], [Enable PCAP output plugin [default=test]])])
AS_IF([test "x$enable_pcap" != "xno"], [

  PKG_CHECK_EXISTS([libpcap], [PKG_CHECK_MODULES([libpcap], [libpcap])], [

    AC_ARG_WITH([pcap-config],
                [AS_HELP_STRING([--with-pcap-config=PATH], [Path to the pcap-config script])],
                [pcap_config="$withval"], [pcap_config=pcap-config])

    AC_MSG_CHECKING([for pcap-config])

    AS_IF([command -v "$pcap_config" >/dev/null], [

      libpcap_CFLAGS="`$pcap_config --cflags`"
      libpcap_LIBS="`$pcap_config --libs`"

      AC_SUBST([libpcap_CFLAGS])
      AC_SUBST([libpcap_LIBS])

      AC_MSG_RESULT([$pcap_config])

    ], [
      AC_MSG_RESULT([no])
    ])

    AS_IF([test "x$libpcap_LIBS" = "x"], [
      AS_IF([test "x$enable_pcap" = "xyes"], [
        AC_MSG_ERROR([libpcap not found])
      ])
    ])

  ])

])
AS_IF([test "x$libpcap_LIBS" != "x"], [enable_pcap=yes], [enable_pcap=no])
AM_CONDITIONAL([HAVE_PCAP], [test "x$libpcap_LIBS" != "x"])

AC_ARG_ENABLE([json],
              [AS_HELP_STRING([--enable-json], [Enable JSON output plugin [default=test]])])
AS_IF([test "x$enable_json" != "xno"],
      [PKG_CHECK_MODULES([libjansson], [jansson], [], [:])])
AS_IF([test "x$libjansson_LIBS" != "x"], [enable_json=yes], [enable_json=no])
AM_CONDITIONAL([HAVE_JANSSON], [test "x$libjansson_LIBS" != "x"])

AC_ARG_ENABLE([namespace],
              [AS_HELP_STRING([--enable-namespace], [Enable linux namespace functionality in plugins supporting it [default=test]])])
AS_IF([test "x$enable_namespace" != "xno"], [
  AC_CHECK_DECLS([setns, CLONE_NEWNET], [
    enable_namespace=yes
  ], [
    AS_IF([test "x$enable_namespace" = "xyes"], [
      AC_MSG_ERROR([linux namespace support enabled, but required symbols not available])
    ], [
      enable_namespace=no
    ])
  ], [[
    #define _GNU_SOURCE 1
    #include <fcntl.h>
    #include <sched.h>
  ]])
])
AS_IF([test "x$enable_namespace" = "xyes"], [
  AC_DEFINE([ENABLE_NAMESPACE], [1], [Define to 1 if you want linux namespace support.])
])

AC_ARG_WITH([ulogd2libdir],
            [AS_HELP_STRING([--with-ulogd2libdir=PATH], [Default directory to load ulogd2 plugin from [[LIBDIR/ulogd]]])],
            [ulogd2libdir="$withval"],
            [ulogd2libdir="${libdir}/ulogd"])
AC_SUBST([ulogd2libdir])

AC_CONFIG_FILES([Makefile
		 filter/Makefile
		 filter/raw2packet/Makefile
		 include/Makefile
		 include/linux/Makefile
		 include/linux/netfilter/Makefile
		 include/ulogd/Makefile
		 input/Makefile
		 input/flow/Makefile
		 input/packet/Makefile
		 input/sum/Makefile
		 output/Makefile
		 output/dbi/Makefile
		 output/ipfix/Makefile
		 output/mysql/Makefile
		 output/pcap/Makefile
		 output/pgsql/Makefile
		 output/sqlite3/Makefile
		 src/Makefile])

AC_OUTPUT

define([EXPAND_VARIABLE],
[$2=[$]$1
if test $prefix = 'NONE'; then
        prefix="/usr/local"
fi
while true; do
  case "[$]$2" in
    *\[$]* ) eval "$2=[$]$2" ;;
    *) break ;;
  esac
done
eval "$2=[$]$2"
])dnl EXPAND_VARIABLE

EXPAND_VARIABLE(ulogd2libdir, e_ulogd2libdir)

echo "
Ulogd configuration:
  Default plugins directory:		${e_ulogd2libdir}
  Linux namespace support:		${enable_namespace}
  Input plugins:
    NFLOG plugin:			${enable_nflog}
    NFCT plugin:			${enable_nfct}
    NFACCT plugin:			${enable_nfacct}
  Output plugins:
    PCAP plugin:			${enable_pcap}
    PGSQL plugin:			${enable_pgsql}
    MySQL plugin:			${enable_mysql}
    SQLITE3 plugin:			${enable_sqlite3}
    DBI plugin:				${enable_dbi}
    JSON plugin:			${enable_json}
"
echo "You can now run 'make' and 'make install'"
