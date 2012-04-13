libdir = $(PAMDIR)

SUBDIRS = lib utils

lib_LTLIBRARIES = pam_yubikey.la

pam_yubikey_la_SOURCES = pam_yubikey.c
pam_yubikey_la_LDFLAGS = -module -avoid-version
pam_yubikey_la_LIBADD = lib/libyubipam.la -lpam

# Self tests
AM_LDFLAGS = -no-install
LDADD = ./pam_yubikey.la -lpam

check_PROGRAMS = test
TESTS = $(check_PROGRAMS)

install-data-hook:
	-rm $(DESTDIR)$(libdir)/pam_yubikey.la
	-rm $(DESTDIR)$(libdir)/pam_yubikey.a

