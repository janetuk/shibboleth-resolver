AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = doc src

DIST_SUBDIRS = doc src

GENFILES = resolver.spec Portfile

EXTRA_DIST = \
    cpp-sp-resolver.sln \
    $(GENFILES) \
    $(GENFILES:%=%.in) \
    config_win32.h
