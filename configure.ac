dnl
dnl File:        configure.in
dnl Revision:    $Id: configure.ac,v 1.0 2012/04/13 12:04:29 j-nijhof Exp $
dnl Created:     2012/04/13
dnl Author:      Jeroen Nijhof <jeroen@jeroennijhof.nl>
dnl
dnl Process this file with autoconf to produce a configure script
dnl You need autoconf 2.59 or better!
dnl
dnl ---------------------------------------------------------------------------

AC_PREREQ(2.59)
AC_COPYRIGHT([
See the included file: COPYING for copyright information.
])
AC_INIT(src/pam_yubikey.c, 1.0.5, [firnsy@securixlive.com,jeroen@jeroennijhof.nl])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/pam_yubikey.c])
AC_CONFIG_HEADER([config.h])

dnl --------------------------------------------------------------------
dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL

AC_SUBST(PAMDIR, "/lib/security")
AC_DEFINE_UNQUOTED([CHKPWD_HELPER], ["${sbindir}/yk_chkpwd"], [Location of yk_chkpwd])

AC_ARG_WITH(pam-dir,
	AC_HELP_STRING([--with-pam-dir=DIR],
			       [Where to install PAM module [[PREFIX/lib/security]]]
				  ),
	[case "${withval}" in
		/*) PAMDIR="${withval}";;
		./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
		*)  PAMDIR="/lib/${withval}";;
	 esac]
)

AC_ARG_WITH(authdb,
	AC_HELP_STRING([--with-authdb],
				   [Select the default authentication database (default is /etc/yubikey)]),
    [
		AC_SUBST(AUTH_DB_DEFAULT, "$withval")
        AC_DEFINE_UNQUOTED(CONFIG_AUTH_DB_DEFAULT, "$withval")
	],
	[
		AC_SUBST(AUTH_DB_DEFAULT, "/etc/yubikey")
	    AC_DEFINE([CONFIG_AUTH_DB_DEFAULT], ["/etc/yubikey"], [Using default yubikey database])
    ]
)

dnl --------------------------------------------------------------------
dnl Checks for libraries.
AC_CHECK_LIB(pam, pam_start)

dnl --------------------------------------------------------------------
dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h syslog.h unistd.h wchar.h security/pam_appl.h security/pam_modules.h])

dnl --------------------------------------------------------------------
dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

dnl --------------------------------------------------------------------
dnl Checks for library functions.
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([dup2 memset strchr strdup])

dnl --------------------------------------------------------------------
dnl Generate made files
AC_CONFIG_FILES([Makefile src/Makefile src/lib/Makefile src/utils/Makefile])
AC_OUTPUT

