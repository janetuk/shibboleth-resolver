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
 * @file shibresolver/resolver.h
 *
 * An embeddable component interface to Shibboleth SP attribute processing.
 */

#ifndef __shibresolver_h__
#define __shibresolver_h__

#include <shibresolver/base.h>

#include <shibsp/RequestMapper.h>
#include <shibsp/SPConfig.h>

#include <string>
#include <vector>

namespace xmltooling {
    class XMLTOOL_API XMLObject;
};

namespace shibsp {
    class SHIBSP_API Attribute;
    class SHIBSP_API SPRequest;
};

namespace shibresolver {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    /**
     * An embeddable component interface to Shibboleth SP attribute processing.
     */
    class SHIBRESOLVER_API ShibbolethResolver
    {
        MAKE_NONCOPYABLE(ShibbolethResolver);
    protected:
        ShibbolethResolver();
    public:
        virtual ~ShibbolethResolver();

        /**
         * Sets the calling service request, making the Shibboleth SP responsible for
         * mapping the service to an Application instance.
         *
         * @param request identifies the service request performing attribute resolution
         */
        void setRequest(const shibsp::SPRequest* request);

        /**
         * Sets the application ID to use for resolution, bypassing the mapping
         * function of the Shibboleth SP.
         *
         * @param appID identifies an application in the SP configuration
         */
        void setApplicationID(const char* appID);

        /**
         * Sets the identity issuer to use for resolution.
         *
         * @param issuer    entityID of the identity "source", if known
         */
        void setIssuer(const char* issuer);

        /**
         * Adds an XML token as input to the resolver, generally a SAML assertion.
         * <p>The caller retains ownership of the object.
         *
         * @param token an input token to evaluate
         */
        void addToken(const xmltooling::XMLObject* token);

        /**
         * Adds an Attribute as input to the resolver.
         * <p>The caller retains ownership of the object.
         *
         * @param attr  an input Attribute
         */
        void addAttribute(shibsp::Attribute* attr);

        /**
         * Resolves Attributes and attaches them to the resolver object.
         * <p>The caller is responsible for transferring any Attributes it wishes to
         * retain out of the resolver.
         */
        virtual void resolve();

        /**
         * Returns a modifiable array of resolved Attribute objects.
         * <p>The caller may take ownership of any or all by removing them
         * from the array.
         *
         * @return  array of resolved Attributes
         */
        std::vector<shibsp::Attribute*>& getResolvedAttributes();

        /**
         * Returns mapped PropertySet and AccessControl objects, if any.
         *
         * @return  mapped PropertySet/AccesssControl pair
         */
        shibsp::RequestMapper::Settings getSettings() const;

        /**
         * Initializes SP runtime objects based on an XML configuration string or a configuration pathname.
         * <p>Each process using the library MUST call this function exactly once before using any library classes.
         *
         * @param features  bitmask of SP components to enable
         * @param config    a snippet of XML to parse (it <strong>MUST</strong> contain a type attribute) or a pathname
         * @param rethrow   true iff caught exceptions should be rethrown instead of just returning a true/false result
         * @return true iff initialization was successful
         */
        static bool init(
#ifdef SHIBSP_LITE
            unsigned long features = (shibsp::SPConfig::Listener|shibsp::SPConfig::InProcess),
#else
            unsigned long features = shibsp::SPConfig::OutOfProcess,
#endif
            const char* config = NULL,
            bool rethrow = false
            );

        /**
         * Shuts down runtime.
         *
         * Each process using the library SHOULD call this function exactly once before terminating itself.
         */
        static void term();

        /**
         * Returns a ShibbolethResolver instance.
         *
         * @return  a ShibbolethResolver instance, must be freed by the caller.
         */
        static ShibbolethResolver* create();

    protected:
        /** Service request. */
        const shibsp::SPRequest* m_request;

        /** Application ID. */
        std::string m_appID;

        /** Source of identity, if known. */
        std::string m_issuer;

        /** Input tokens. */
        std::vector<const xmltooling::XMLObject*> m_tokens;

        /** Input attributes. */
        std::vector<shibsp::Attribute*> m_inputAttributes;

    private:
        shibsp::ServiceProvider* m_sp;
        std::vector<shibsp::Attribute*> m_resolvedAttributes;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibresolver_h__ */
