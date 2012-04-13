AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = ykvalidate ykdump
sbin_PROGRAMS = ykpasswd yk_chkpwd

ykpasswd_SOURCES = ykpasswd.c ykpasswd.h ykversion.h
ykpasswd_LDADD = ../lib/libyubipam.la

ykdump_SOURCES = ykdump.c ykdump.h ykversion.h
ykdump_LDADD = ../lib/libyubipam.la

ykvalidate_SOURCES = ykvalidate.c ykvalidate.h ykversion.h
ykvalidate_LDADD = ../lib/libyubipam.la

yk_chkpwd_SOURCES = yk_chkpwd.c
yk_chkpwd_LDADD = ../lib/libyubipam.la

INCLUDES = -I../ -I../lib

