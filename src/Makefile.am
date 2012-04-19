libdir = $(PAMDIR)

SUBDIRS = lib utils

lib_LTLIBRARIES = pam_yubikey.la

pam_yubikey_la_SOURCES = pam_yubikey.c
pam_yubikey_la_LDFLAGS = -module -avoid-version
pam_yubikey_la_LIBADD = lib/libyubipam.la -lpam

AM_CFLAGS = -Wall
INCLUDES = -Ilib

install-data-hook:
	-rm $(DESTDIR)$(libdir)/pam_yubikey.la
	-rm $(DESTDIR)$(libdir)/pam_yubikey.a

