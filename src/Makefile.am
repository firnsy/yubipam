libdir = $(PAMDIR)

SUBDIRS = lib utils

lib_LTLIBRARIES = pam_yubikey.la
#am_yubikey_PROGRAMS = pam_yubikey.so
#pam_yubikeydir = /lib/security

pam_yubikey_la_SOURCES = pam_yubikey.c
pam_yubikey_la_LDFLAGS = -module -avoid-version
pam_yubikey_la_LIBADD = lib/libyubipam.la -lpam


# Self tests
AM_LDFLAGS = -no-install
LDADD = ./pam_yubikey.la -lpam

check_PROGRAMS = test
TESTS = $(check_PROGRAMS)

DEFS = @DEFS@
INCLUDES = -Ilib @INCLUDES@

