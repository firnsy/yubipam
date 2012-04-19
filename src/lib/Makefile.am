AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LTLIBRARIES = libyubipam.la

noinst_HEADERS = yubikey_common.h libyubipam.h

libyubipam_la_SOURCES = yubikey_db.c yubikey_db.h \
yubikey_util.c yubikey_util.h \
yubikey_err.h yubikey_err.c

AM_CFLAGS = -Wall
INCLUDES = -I../

