AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libshibresolver.la libshibresolver-lite.la

libshibresolverincludedir = $(includedir)/shibresolver

libshibresolverinclude_HEADERS = \
	shibresolver/base.h \
	shibresolver/config_pub.h \
	shibresolver/resolver.h

noinst_HEADERS = \
	shibresolver/internal.h

common_sources = \
	shibresolver/resolver.cpp

libshibresolver_la_SOURCES = \
	${common_sources}

libshibresolver_lite_la_SOURCES = \
	${common_sources}

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshibresolver_la_LDFLAGS = $(XMLSEC_LIBS) -version-info 1:0:0
libshibresolver_lite_la_LDFLAGS = $(LITE_LIBS) -version-info 1:0:0
libshibresolver_lite_la_CPPFLAGS = -DSHIBSP_LITE

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = \
	resolver.vcxproj \
	resolver-lite.vcxproj \
	shibresolver/config_pub.h.in \
	shibresolver/config_pub_win32.h \
	shibresolver/resource.h \
	shibresolver/resolver.rc
