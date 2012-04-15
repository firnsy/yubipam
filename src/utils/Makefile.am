AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = ykvalidate ykdump
sbin_PROGRAMS = ykpasswd yk_chkpwd

ykpasswd_SOURCES = ykpasswd.c ykpasswd.h ykversion.h ykversion.c
ykpasswd_LDADD = ../lib/libyubipam.la

ykdump_SOURCES = ykdump.c ykdump.h ykversion.h ykversion.c
ykdump_LDADD = ../lib/libyubipam.la

ykvalidate_SOURCES = ykvalidate.c ykvalidate.h ykversion.h ykversion.c
ykvalidate_LDADD = ../lib/libyubipam.la

yk_chkpwd_SOURCES = yk_chkpwd.c
yk_chkpwd_LDADD = ../lib/libyubipam.la

AM_CFLAGS = -Wall
INCLUDES = -I../ -I../lib

