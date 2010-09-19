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

#include <shibsp/ServiceProvider.h>
#include <shibsp/attribute/Attribute.h>
#include <shibsp/remoting/ListenerService.h>

using namespace shibresolver;
using namespace shibsp;
#ifndef SHIBSP_LITE
using namespace opensaml;
#endif
using namespace xmltooling;
using namespace std;

namespace shibresolver {
    class SHIBRESOLVER_DLLLOCAL RemotedResolver : public Remoted {
    public:
        RemotedResolver() {}
        ~RemotedResolver() {}

        void receive(DDF& in, ostream& out);
    };

    static RemotedResolver g_Remoted;
};

ShibbolethResolver* ShibbolethResolver::create()
{
    return new ShibbolethResolver();
}

ShibbolethResolver::ShibbolethResolver()
{
}

ShibbolethResolver::~ShibbolethResolver()
{
    for_each(m_resolvedAttributes.begin(), m_resolvedAttributes.end(), xmltooling::cleanup<Attribute>());
    if (m_mapper)
        m_mapper->unlock();
    if (m_sp)
        m_sp->unlock();
}

void ShibbolethResolver::setServiceURI(const char* uri)
{
    m_serviceURI.erase();
    if (uri)
        m_serviceURI = uri;
}

void ShibbolethResolver::setApplicationID(const char* appID)
{
    m_appID.erase();
    if (appID)
        m_appID = appID;
}

void ShibbolethResolver::setIssuer(const char* issuer)
{
    m_issuer.erase();
    if (issuer)
        m_issuer = issuer;
}

void ShibbolethResolver::addToken(
#ifdef SHIBSP_LITE
        const XMLObject* token
#else
        const saml2::Assertion* token
#endif
    )
{
    if (token)
        m_tokens.push_back(token);
}

void ShibbolethResolver::addAttribute(Attribute* attr)
{
    if (attr)
        m_inputAttributes.push_back(attr);
}

vector<Attribute*>& ShibbolethResolver::getResolvedAttributes()
{
    return m_resolvedAttributes;
}

RequestMapper::Settings ShibbolethResolver::getSettings() const
{
    return m_settings;
}

void ShibbolethResolver::resolve()
{
}

void RemotedResolver::receive(DDF& in, ostream& out)
{
}

extern "C" int SHIBRESOLVER_EXPORTS xmltooling_extension_init(void*)
{
#ifdef SHIBRESOLVER_SHIBSP_HAS_REMOTING
    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::OutOfProcess) && !conf.isEnabled(SPConfig::InProcess) && conf.isEnabled(SPConfig::Listener))
        conf.getServiceProvider()->regListener("org.project-moonshot.shibresolver", &g_Remoted);
#endif
    return 0;   // signal success
}

extern "C" void SHIBRESOLVER_EXPORTS xmltooling_extension_term()
{
    // Factories normally get unregistered during library shutdown, so no work usually required here.
}
