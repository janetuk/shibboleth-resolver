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
 * resolver.cpp
 *
 * An embeddable component interface to Shibboleth SP attribute processing.
 */

#include "internal.h"

using namespace shibsp;
#ifndef SHIBSP_LITE
using namespace opensaml;
#endif
using namespace xmltooling;
using namespace std;

extern "C" int SHIBRESOLVER_EXPORTS xmltooling_extension_init(void*)
{
    // Register factory functions with appropriate plugin managers in the XMLTooling/SAML/SPConfig objects.
    return 0;   // signal success
}

extern "C" void SHIBRESOLVER_EXPORTS xmltooling_extension_term()
{
    // Factories normally get unregistered during library shutdown, so no work usually required here.
}
