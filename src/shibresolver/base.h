/*
 *  Copyright 2010 JANET(UK)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file shibresolver/base.h
 *
 * Base header file definitions
 * Must be included prior to including any other header
 */

#ifndef __shibresolver_base_h__
#define __shibresolver_base_h__

#include <shibsp/base.h>

// Windows and GCC4 Symbol Visibility Macros
#ifdef WIN32
  #define SHIBRESOLVER_IMPORT __declspec(dllimport)
  #define SHIBRESOLVER_EXPORT __declspec(dllexport)
  #define SHIBRESOLVER_DLLLOCAL
  #define SHIBRESOLVER_DLLPUBLIC
#else
  #define SHIBRESOLVER_IMPORT
  #ifdef GCC_HASCLASSVISIBILITY
    #define SHIBRESOLVER_EXPORT __attribute__ ((visibility("default")))
    #define SHIBRESOLVER_DLLLOCAL __attribute__ ((visibility("hidden")))
    #define SHIBRESOLVER_DLLPUBLIC __attribute__ ((visibility("default")))
  #else
    #define SHIBRESOLVER_EXPORT
    #define SHIBRESOLVER_DLLLOCAL
    #define SHIBRESOLVER_DLLPUBLIC
  #endif
#endif

// Define SHIBRESOLVER_API for DLL builds
#ifdef SHIBRESOLVER_EXPORTS
  #define SHIBRESOLVER_API SHIBRESOLVER_EXPORT
#else
  #define SHIBRESOLVER_API SHIBRESOLVER_IMPORT
#endif

// Throwable classes must always be visible on GCC in all binaries
#ifdef WIN32
  #define SHIBRESOLVER_EXCEPTIONAPI(api) api
#elif defined(GCC_HASCLASSVISIBILITY)
  #define SHIBRESOLVER_EXCEPTIONAPI(api) SHIBRESOLVER_EXPORT
#else
  #define SHIBRESOLVER_EXCEPTIONAPI(api)
#endif

/** Logging category for Service Provider functions. */
#define SHIBRESOLVER_LOGCAT "ShibbolethResolver"

#endif /* __shibresolver_base_h__ */
