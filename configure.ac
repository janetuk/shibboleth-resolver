AC_PREREQ([2.50])
AC_INIT([shibboleth-resolver], [0.3], [MOONSHOT-COMMUNITY@JISCMAIL.AC.UK], [shibboleth-resolver])
AC_CONFIG_SRCDIR(src)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Have GCC compile with symbols (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
fi

AC_CONFIG_HEADERS([config.h src/shibresolver/config_pub.h])
AC_CONFIG_FILES([resolver.spec Portfile])
AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile])

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])
AC_CANONICAL_HOST

if test "$GCC" = "yes" ; then
#    AC_HAVE_GCC_VERSION(4,0,0,0,
#        [
#        AC_DEFINE(GCC_HASCLASSVISIBILITY,1,
#            [Define to enable class visibility control in gcc.])
#        GCC_CFLAGS="$GCC_CFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
#        GCC_CXXFLAGS="$GCC_CXXFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
#        ])
    CFLAGS="-Wall $GCC_CFLAGS"
    CXXFLAGS="-Wall $GCC_CXXFLAGS"
fi

# Fix for Sun Workshop compiler in debug mode, may be Sun case #6360993
# Also enables POSIX semantics for some functions.
case "${host_cpu}-${host_os}" in
    *solaris*)
	CFLAGS="$CFLAGS -D_POSIX_PTHREAD_SEMANTICS"
	CXXFLAGS="$CXXFLAGS -D_POSIX_PTHREAD_SEMANTICS"
	if test "$CXX" = "CC" ; then
		CXXFLAGS="$CXXFLAGS -Qoption ccfe -stabs=no%dfltlit+no%dflthlp"
	fi
    ;;
esac

AC_LANG(C)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp])

# checks for pthreads
ACX_PTHREAD([enable_threads="pthread"],[enable_threads="no"])
if test $enable_threads != "pthread"; then
    AC_MSG_ERROR([unable to find pthreads, currently this is required])
else
    AC_DEFINE([HAVE_PTHREAD],[1],[Define if you have POSIX threads libraries and header files.])
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
    CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS"
fi

AC_LANG(C++)

# C++ requirements
AC_CXX_NAMESPACES
AC_CXX_REQUIRE_STL

# are covariant methods allowed?
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[]],
        [[
        class base { public: virtual base *GetPtr( void ) { return this; } };
        class derived: virtual public base { public: virtual derived *GetPtr( void ) { return this; } };
        ]])],
    [AC_DEFINE([HAVE_COVARIANT_RETURNS],[1],[Define to 1 if C++ compiler supports covariant virtual methods.])])

# is nullptr supported?
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[]],[[const char* ptr = nullptr;]])],
    [AC_DEFINE([HAVE_NULLPTR],[1],[Define to 1 if C++ compiler supports nullptr keyword.])])

# log4shib settings (favor this version over the log4cpp code)
AC_PATH_PROG(LOG4SHIB_CONFIG,log4shib-config)
AC_ARG_WITH(log4shib,
    AS_HELP_STRING([--with-log4shib=PATH],[where log4shib-config is installed]),
    [
    LOG4SHIB_CONFIG="${with_log4shib}"
    if ! test -f "${LOG4SHIB_CONFIG}" ; then
    	LOG4SHIB_CONFIG="${with_log4shib}/bin/log4shib-config"
    fi
    ])
if test -f "${LOG4SHIB_CONFIG}"; then
    LIBS="`${LOG4SHIB_CONFIG} --libs` $LIBS"
    CPPFLAGS="`${LOG4SHIB_CONFIG} --cflags` $CPPFLAGS"
	AC_CHECK_HEADER([log4shib/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4shib header files]))
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[#include <log4shib/Category.hh>
#include <log4shib/CategoryStream.hh>]],
            [[log4shib::Category::getInstance("foo").errorStream() << log4shib::eol]])],
        [AC_DEFINE([SHIBRESOLVER_LOG4SHIB],[1],[Define to 1 if log4shib library is used.])],
        [AC_MSG_ERROR([unable to link with log4shib])])
else
    AC_MSG_WARN([log4shib-config not found, may need to use --with-log4shib option])
    AC_MSG_WARN([will look for original log4cpp library])
    
	# log4cpp settings
	AC_PATH_PROG(LOG4CPP_CONFIG,log4cpp-config)
	AC_ARG_WITH(log4cpp,
	    AS_HELP_STRING([--with-log4cpp=PATH],[where log4cpp-config is installed]),
	    [
	    LOG4CPP_CONFIG="${with_log4cpp}"
	    if ! test -f "${LOG4CPP_CONFIG}" ; then
	    	LOG4CPP_CONFIG="${with_log4cpp}/bin/log4cpp-config"
	    fi
	    ])
	if test -f "${LOG4CPP_CONFIG}"; then
		AC_MSG_WARN([will try to use log4cpp, note that most non-Internet2 supplied versions are not thread-safe])
	    LIBS="`${LOG4CPP_CONFIG} --libs` $LIBS"
	    CPPFLAGS="`${LOG4CPP_CONFIG} --cflags` $CPPFLAGS"
		AC_CHECK_HEADER([log4cpp/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4cpp header files]))
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM([[#include <log4cpp/Category.hh>
#include <log4cpp/CategoryStream.hh>]],
                [[log4cpp::Category::getInstance("foo").errorStream() << log4cpp::eol]])],
            [AC_DEFINE([SHIBRESOLVER_LOG4CPP],[1],[Define to 1 if log4cpp library is used.])],
            [AC_MSG_ERROR([unable to link with log4cpp, need version 1.0 or later])])
	else
	    AC_MSG_ERROR([log4cpp-config not found, may need to use --with-log4cpp option])
	fi
fi

# Xerces settings
# Xerces settings
AC_ARG_WITH(xerces,
    AS_HELP_STRING([--with-xerces=PATH],[where xerces-c is installed]),
    [if test x_$with_xerces != x_/usr; then
        LDFLAGS="-L${with_xerces}/lib $LDFLAGS"
        CPPFLAGS="-I${with_xerces}/include $CPPFLAGS"
    fi])
LIBS="-lxerces-c $LIBS"
AC_CHECK_HEADER([xercesc/dom/DOM.hpp],,AC_MSG_ERROR([unable to find xerces header files]))
AC_MSG_CHECKING([Xerces version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xercesc/util/XercesVersion.hpp>],
[#if  _XERCES_VERSION != 20600
int i = 0;
#else
#error cannot use version 2.6.0
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([Xerces-C v2.6.0 has bugs that inhibit use with signed XML, please use a newer version])])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <xercesc/util/PlatformUtils.hpp>]],
        [[xercesc::XMLPlatformUtils::Initialize()]])],
    ,[AC_MSG_ERROR([unable to link with Xerces])])


#XML-Tooling settings
AC_ARG_WITH(xmltooling,
    AS_HELP_STRING([--with-xmltooling=PATH],[where xmltooling-c is installed]),
    [if test x_$with_xmltooling != x_/usr; then
        LDFLAGS="-L${with_xmltooling}/lib $LDFLAGS"
        CPPFLAGS="-I${with_xmltooling}/include $CPPFLAGS"
    fi])
LITE_LIBS="-lxmltooling-lite"
XMLSEC_LIBS="-lxmltooling"
AC_CHECK_HEADER([xmltooling/base.h],,AC_MSG_ERROR([unable to find xmltooling header files]))

# XML-Security settings
AC_ARG_WITH(xmlsec,
    AS_HELP_STRING([--with-xmlsec=PATH], [where xmlsec is installed]),,
    [with_xmlsec=/usr])

if test x_$with_xmlsec != x_/usr; then
    LDFLAGS="-L${with_xmlsec}/lib $LDFLAGS"
    CPPFLAGS="-I${with_xmlsec}/include $CPPFLAGS"
fi        
XMLSEC_LIBS="-lxml-security-c $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([xsec/utils/XSECPlatformUtils.hpp],,AC_MSG_ERROR([unable to find XML-Security header files]))
AC_MSG_CHECKING([XML-Security version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xsec/utils/XSECPlatformUtils.hpp>],
    [#if XSEC_VERSION_MAJOR > 1 || (XSEC_VERSION_MAJOR == 1 && XSEC_VERSION_MEDIUM > 3)
int i = 0;
#else
#error need version 1.4.0 or later
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([XML-Security version 1.4.0 or greater is required.])])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <xsec/utils/XSECPlatformUtils.hpp>]],
        [[XSECPlatformUtils::Initialise()]])],,
    [AC_MSG_ERROR([unable to link with XML-Security])])

# restore master libs
LIBS="$save_LIBS"

# OpenSAML settings
AC_ARG_WITH(saml,
    AS_HELP_STRING([--with-saml=PATH],[where saml is installed]),
    [if test x_$with_saml != x_/usr; then
        LDFLAGS="-L${with_saml}/lib $LDFLAGS"
        CPPFLAGS="-I${with_saml}/include $CPPFLAGS"
    fi])
XMLSEC_LIBS="-lsaml $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([saml/saml2/metadata/Metadata.h],,AC_MSG_ERROR([unable to find OpenSAML header files]))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <saml/SAMLConfig.h>]],
    [[opensaml::SAMLConfig::getConfig()]])],
    ,[AC_MSG_ERROR([unable to link with OpenSAML])])

# restore master libs
LIBS="$save_LIBS"

# Shibboleth SP settings
AC_ARG_WITH(shibsp,
    AS_HELP_STRING([--with-shibsp=PATH],[where Shibboleth SP is installed]),
    [if test x_$with_shibsp != x_/usr; then
        LDFLAGS="-L${with_shibsp}/lib $LDFLAGS"
        CPPFLAGS="-I${with_shibsp}/include $CPPFLAGS"
    fi])
LITE_LIBS="-lshibsp-lite $LITE_LIBS"
XMLSEC_LIBS="-lshibsp $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([shibsp/SPConfig.h],,AC_MSG_ERROR([unable to find Shibboleth SP header files]))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <shibsp/SPConfig.h>]],
    [[shibsp::SPConfig::getConfig()]])],
    ,[AC_MSG_ERROR([unable to link with Shibboleth SP])])

AC_MSG_CHECKING([whether SP library supports non-plugin remoting])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
    [[
#include <vector>
#include <shibsp/ServiceProvider.h>
    ]],
    [[shibsp::ServiceProvider* sp; sp->regListener(NULL,NULL);]])],
    [AC_MSG_RESULT([yes])AC_DEFINE([SHIBRESOLVER_SHIBSP_HAS_REMOTING],[1],[Define to 1 if Shibboleth SP supports non-plugin remoting.])],
    [AC_MSG_RESULT([no])])

# restore master libs
LIBS="$save_LIBS"

# GSS-API checking

GSSAPI_ROOT="/usr"
AC_ARG_WITH(gssapi-includes,
  AS_HELP_STRING([--with-gssapi-includes=DIR],[Specify location of GSSAPI header]),
  [ GSSAPI_INCS="-I$withval"
    want_gss="yes" ]
)

AC_ARG_WITH(gssapi-libs,
  AS_HELP_STRING([--with-gssapi-libs=DIR],[Specify location of GSSAPI libs]),
  [ GSSAPI_LIB_DIR="-L$withval"
    want_gss="yes" ]
)

AC_ARG_WITH(gssapi,
  AS_HELP_STRING([--with-gssapi=DIR],[Where to look for GSSAPI]),
  [ GSSAPI_ROOT="$withval"
  if test x"$GSSAPI_ROOT" != xno; then
    want_gss="yes"
    if test x"$GSSAPI_ROOT" = xyes; then
      dnl if yes, then use default root
      GSSAPI_ROOT="/usr"
    fi
  fi
])

save_CPPFLAGS="$CPPFLAGS"
AC_MSG_CHECKING([if GSSAPI support is requested])
if test x"$want_gss" = xyes; then
  AC_MSG_RESULT(yes)

  if test -z "$GSSAPI_INCS"; then
     if test -f "$GSSAPI_ROOT/bin/krb5-config"; then
        GSSAPI_INCS=`$GSSAPI_ROOT/bin/krb5-config --cflags gssapi`
     elif test "$GSSAPI_ROOT" != "yes"; then
        GSSAPI_INCS="-I$GSSAPI_ROOT/include"
     fi
  fi

  CPPFLAGS="$CPPFLAGS $GSSAPI_INCS"

  AC_CHECK_HEADER(gss.h,
    [
      dnl found in the given dirs
      AC_DEFINE([SHIBRESOLVER_HAVE_GSSGNU],[1],[if you have the GNU gssapi libraries])
      gnu_gss=yes
    ],
    [
      dnl not found, check Heimdal or MIT
      AC_CHECK_HEADERS([gssapi/gssapi.h], [], [not_mit=1])
      AC_CHECK_HEADERS(
        [gssapi/gssapi_generic.h gssapi/gssapi_krb5.h],
        [],
        [not_mit=1],
        [
AC_INCLUDES_DEFAULT
#ifdef HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#endif
        ])
      if test "x$not_mit" = "x1"; then
        dnl MIT not found, check for Heimdal
        AC_CHECK_HEADER([gssapi.h],
            [
              dnl found
              AC_DEFINE([SHIBRESOLVER_HAVE_GSSHEIMDAL],[1],[if you have the Heimdal gssapi libraries])
            ],
            [
              dnl no header found, disabling GSS
              want_gss=no
              AC_MSG_WARN([disabling GSSAPI since no header files was found])
            ]
          )
      else
        dnl MIT found
        AC_DEFINE([SHIBRESOLVER_HAVE_GSSMIT],[1],[if you have the MIT gssapi libraries])
        dnl check if we have a really old MIT kerberos (<= 1.2)
        AC_MSG_CHECKING([if gssapi headers declare GSS_C_NT_HOSTBASED_SERVICE])
        AC_COMPILE_IFELSE([
          AC_LANG_PROGRAM([[
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
          ]],[[
            gss_import_name(
                            (OM_uint32 *)0,
                            (gss_buffer_t)0,
                            GSS_C_NT_HOSTBASED_SERVICE,
                            (gss_name_t *)0);
          ]])
        ],[
          AC_MSG_RESULT([yes])
        ],[
          AC_MSG_RESULT([no])
          AC_DEFINE([HAVE_OLD_GSSMIT],[1],[if you have an old MIT gssapi library, lacking GSS_C_NT_HOSTBASED_SERVICE])
        ])
      fi
    ]
  )
else
  AC_MSG_RESULT(no)
fi
if test x"$want_gss" = xyes; then
  AC_DEFINE([SHIBRESOLVER_HAVE_GSSAPI],[1],[if you have the gssapi libraries])

  if test -n "$gnu_gss"; then
    LDFLAGS="$LDFLAGS $GSSAPI_LIB_DIR"
    LIBS="$LIBS -lgss"
  else
    if test -z "$GSSAPI_LIB_DIR"; then
      GSSAPI_LIB_DIR="$GSSAPI_ROOT/lib$libsuff"
    fi
    if test "$GSSAPI_ROOT" != "yes"; then
       LDFLAGS="$LDFLAGS -L$GSSAPI_ROOT/lib$libsuff"
    fi
    if test -f "$GSSAPI_ROOT/bin/krb5-config"; then
      dnl krb5-config does not have --libs-only-L or similar, put everything into LIBS
      gss_libs=`$GSSAPI_ROOT/bin/krb5-config --libs gssapi`
    else
      if test "x$not_mit" = "x1"; then
        gss_libs="-lgssapi"
      else
        gss_libs="-lgssapi_krb5"
      fi
    fi
    LIBS="$LIBS $gss_libs"
  fi

  AC_MSG_CHECKING([whether GSS-API naming extensions are available])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#ifdef SHIBRESOLVER_HAVE_GSSGNU
# include <gss.h>
#elif defined SHIBRESOLVER_HAVE_GSSMIT
# include <gssapi/gssapi.h>
# include <gssapi/gssapi_ext.h>
#else
# include <gssapi.h>
#endif]],
    [[gss_get_name_attribute(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);]])],
    [AC_MSG_RESULT([yes])AC_DEFINE([SHIBRESOLVER_HAVE_GSSAPI_NAMINGEXTS],[1],[Define to 1 if GSS-API naming extensions are available.])],
    [AC_MSG_RESULT([no])])

else
  CPPFLAGS="$save_CPPFLAGS"
fi


AC_SUBST(LITE_LIBS)
AC_SUBST(XMLSEC_LIBS)

LIBTOOL="$LIBTOOL --silent"

AC_OUTPUT
