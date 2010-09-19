AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

SUBDIRS = doc shibresolver

DIST_SUBDIRS = doc shibresolver

GENFILES = resolver.spec Portfile

EXTRA_DIST = \
    cpp-sp-resolver.sln \
    libtool.m4 \
    acx_pthread.m4 \
    acinclude.m4 \
    $(GENFILES) \
    $(GENFILES:%=%.in) \
    depend \
	depcomp \
    config_win32.h
