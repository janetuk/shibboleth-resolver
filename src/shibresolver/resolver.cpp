/**
 * See the NOTICE file distributed with this work for information
 * regarding copyright ownership. Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
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

#ifdef SHIBRESOLVER_HAVE_GSSAPI_NAMINGEXTS
# ifdef SHIBRESOLVER_HAVE_GSSMIT
#  include <gssapi/gssapi_ext.h>
# endif
#endif

#include <shibsp/exceptions.h>
#include <shibsp/Application.h>
#include <shibsp/GSSRequest.h>
#include <shibsp/SPRequest.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/attribute/Attribute.h>
#include <shibsp/remoting/ListenerService.h>
#ifndef SHIBSP_LITE
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataProvider.h>
# include <saml/util/SAMLConstants.h>
# include <shibsp/attribute/filtering/AttributeFilter.h>
# include <shibsp/attribute/filtering/BasicFilteringContext.h>
# include <shibsp/attribute/resolver/AttributeExtractor.h>
# include <shibsp/attribute/resolver/AttributeResolver.h>
# include <shibsp/attribute/resolver/ResolutionContext.h>
# include <shibsp/metadata/MetadataProviderCriteria.h>
#endif
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/Base64.hpp>

using namespace shibresolver;
using namespace shibsp;
#ifndef SHIBSP_LITE
using namespace opensaml;
using namespace opensaml::saml2md;
#endif
using namespace xmltooling;
using namespace std;

namespace shibresolver {
    class SHIBRESOLVER_DLLLOCAL RemotedResolver : public Remoted {
    public:
        RemotedResolver() {}
        ~RemotedResolver() {}

        struct Transaction {
            ~Transaction() {
                for_each(tokens.begin(), tokens.end(), xmltooling::cleanup<XMLObject>());
                for_each(inputAttrs.begin(), inputAttrs.end(), xmltooling::cleanup<Attribute>());
                for_each(resolvedAttrs.begin(), resolvedAttrs.end(), xmltooling::cleanup<Attribute>());
            }

            vector<const XMLObject*> tokens;
            vector<Attribute*> inputAttrs;
            vector<Attribute*> resolvedAttrs;
        };

        void receive(DDF& in, ostream& out);
        void resolve(
            const Application& app,
            const char* issuer,
            const XMLCh* protocol,
            const vector<const XMLObject*>& tokens,
            const vector<Attribute*>& inputAttrs,
            vector<Attribute*>& resolvedAttrs
            ) const;

    private:
#ifndef SHIBSP_LITE
        void resolve(
            AttributeExtractor* extractor,
            const Application& app,
            const RoleDescriptor* issuer,
            const XMLObject& token,
            vector<Attribute*>& resolvedAttrs
            ) const;

        const RoleDescriptor* lookup(
            const Application& app,
            MetadataProvider* m,
            const char* entityID,
            const XMLCh* protocol
            ) const;
#endif
    };

    static RemotedResolver g_Remoted;
};

ShibbolethResolver* ShibbolethResolver::create()
{
    return new ShibbolethResolver();
}

ShibbolethResolver::ShibbolethResolver() : m_request(NULL), m_sp(NULL)
#ifdef SHIBRESOLVER_HAVE_GSSAPI
        ,m_gsswrapper(NULL)
#endif
{
}

ShibbolethResolver::~ShibbolethResolver()
{
#ifdef SHIBRESOLVER_HAVE_GSSAPI
    delete m_gsswrapper;
#endif
    for_each(m_resolvedAttributes.begin(), m_resolvedAttributes.end(), xmltooling::cleanup<Attribute>());
    if (m_sp)
        m_sp->unlock();
}

void ShibbolethResolver::setRequest(const SPRequest* request)
{
    m_request = request;
#if defined(SHIBSP_HAVE_GSSAPI) && defined (SHIBRESOLVER_HAVE_GSSAPI)
    if (request) {
        const GSSRequest* gss = dynamic_cast<const GSSRequest*>(request);
        if (gss) {
            // TODO: fix API to prevent destruction of contexts
            gss_ctx_id_t ctx = gss->getGSSContext();
            addToken(&ctx);
        }
    }
#endif
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

void ShibbolethResolver::setProtocol(const XMLCh* protocol)
{
    m_protocol.erase();
    if (protocol)
        m_protocol = protocol;
}

void ShibbolethResolver::addToken(const XMLObject* token)
{
    if (token)
        m_tokens.push_back(token);
}

#ifdef SHIBRESOLVER_HAVE_GSSAPI
void ShibbolethResolver::addToken(gss_ctx_id_t* ctx)
{
    if (m_gsswrapper) {
        delete m_gsswrapper;
        m_gsswrapper = NULL;
    }

    if (ctx && *ctx != GSS_C_NO_CONTEXT) {
        OM_uint32 minor;
        gss_buffer_desc contextbuf = GSS_C_EMPTY_BUFFER;
        OM_uint32 major = gss_export_sec_context(&minor, ctx, &contextbuf);
        if (major == GSS_S_COMPLETE) {
            xsecsize_t len=0;
            XMLByte* out=Base64::encode(reinterpret_cast<const XMLByte*>(contextbuf.value), contextbuf.length, &len);
            if (out) {
                string s;
                s.append(reinterpret_cast<char*>(out), len);
                auto_ptr_XMLCh temp(s.c_str());
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                XMLString::release(&out);
#else
                XMLString::release((char**)&out);
#endif
                static const XMLCh _GSSAPI[] = UNICODE_LITERAL_13(G,S,S,A,P,I,C,o,n,t,e,x,t);
                m_gsswrapper = new AnyElementImpl(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _GSSAPI);
                m_gsswrapper->setTextContent(temp.get());
            }
            else {
                Category::getInstance(SHIBRESOLVER_LOGCAT).error("error while base64-encoding GSS context");
            }
            gss_release_buffer(&minor, &contextbuf);
        }
        else {
            Category::getInstance(SHIBRESOLVER_LOGCAT).error("error exporting GSS context");
        }
    }
}

#ifdef SHIBRESOLVER_HAVE_GSSAPI_NAMINGEXTS
void ShibbolethResolver::addToken(gss_name_t name)
{
    if (m_gsswrapper) {
        delete m_gsswrapper;
        m_gsswrapper = NULL;
    }

    OM_uint32 minor;
    gss_buffer_desc namebuf = GSS_C_EMPTY_BUFFER;
    OM_uint32 major = gss_export_name_composite(&minor, name, &namebuf);
    if (major == GSS_S_COMPLETE) {
        addToken(&namebuf);
        gss_release_buffer(&minor, &namebuf);
    }
    else {
        Category::getInstance(SHIBRESOLVER_LOGCAT).error("error exporting GSS name");
    }
}
#endif

void ShibbolethResolver::addToken(const gss_buffer_t contextbuf)
{
    if (m_gsswrapper) {
        delete m_gsswrapper;
        m_gsswrapper = NULL;
    }

    xsecsize_t len=0;
    XMLByte* out=Base64::encode(reinterpret_cast<const XMLByte*>(contextbuf->value), contextbuf->length, &len);
    if (out) {
        string s;
        s.append(reinterpret_cast<char*>(out), len);
        auto_ptr_XMLCh temp(s.c_str());
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
        XMLString::release(&out);
#else
        XMLString::release((char**)&out);
#endif
        static const XMLCh _GSSAPI[] = UNICODE_LITERAL_10(G,S,S,A,P,I,N,a,m,e);
        m_gsswrapper = new AnyElementImpl(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _GSSAPI);
        m_gsswrapper->setTextContent(temp.get());
    }
    else {
        Category::getInstance(SHIBRESOLVER_LOGCAT).error("error while base64-encoding GSS name");
    }
}

#endif

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
    if (!m_request)
        throw ConfigurationException("Request settings not available without supplying SPRequest instance.");
    return m_request->getRequestSettings();
}

void ShibbolethResolver::resolve()
{
    Category& log = Category::getInstance(SHIBRESOLVER_LOGCAT);
    SPConfig& conf = SPConfig::getConfig();
    if (!m_request) {
        m_sp = conf.getServiceProvider();
        m_sp->lock();
        if (m_appID.empty())
            m_appID = "default";
    }

    const Application* app = m_request ? &(m_request->getApplication()) : m_sp->getApplication(m_appID.c_str());
    if (!app)
        throw ConfigurationException("Unable to locate application for resolution.");

#ifdef SHIBRESOLVER_HAVE_GSSAPI
    if (m_gsswrapper)
        m_tokens.push_back(m_gsswrapper);
#endif

    if (conf.isEnabled(SPConfig::OutOfProcess)) {
        g_Remoted.resolve(
            *app,
            m_issuer.c_str(),
            m_protocol.c_str(),
            m_tokens,
            m_inputAttributes,
            m_resolvedAttributes
            );
    }
    else {
        // When not out of process, we remote all the message processing.
        DDF out,in = DDF("org.project-moonshot.shibresolver");
        DDFJanitor jin(in), jout(out);
        in.addmember("application_id").string(app->getId());
        if (!m_issuer.empty())
            in.addmember("issuer").string(m_issuer.c_str());
        if (!m_protocol.empty()) {
            auto_ptr_char prot(m_protocol.c_str());
            in.addmember("protocol").string(prot.get());
        }
        if (!m_tokens.empty()) {
            DDF& tokens = in.addmember("tokens").list();
            for (vector<const XMLObject*>::const_iterator t = m_tokens.begin(); t != m_tokens.end(); ++t) {
                ostringstream os;
                os << *(*t);
                tokens.add(DDF(NULL).string(os.str().c_str()));
            }
        }
        if (!m_inputAttributes.empty()) {
            DDF attr;
            DDF& attrs = in.addmember("attributes").list();
            for (vector<Attribute*>::const_iterator a = m_inputAttributes.begin(); a != m_inputAttributes.end(); ++a) {
                attr = (*a)->marshall();
                attrs.add(attr);
            }
        }

        out = (m_request ? m_request->getServiceProvider() : (*m_sp)).getListenerService()->send(in);

        Attribute* attribute;
        DDF attr = out.first();
        while (!attr.isnull()) {
            try {
                attribute = Attribute::unmarshall(attr);
                m_resolvedAttributes.push_back(attribute);
                if (log.isDebugEnabled())
                    log.debug("unmarshalled attribute (ID: %s) with %d value%s",
                        attribute->getId(), attr.first().integer(), attr.first().integer()!=1 ? "s" : "");
            }
            catch (AttributeException& ex) {
                const char* id = attr.first().name();
                log.error("error unmarshalling attribute (ID: %s): %s", id ? id : "none", ex.what());
            }
            attr = out.next();
        }
    }
}

void RemotedResolver::receive(DDF& in, ostream& out)
{
    Category& log = Category::getInstance(SHIBRESOLVER_LOGCAT);

    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        log.error("couldn't find application (%s) for resolution", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for resolution, deleted?");
    }

    DDF ret(NULL);
    DDFJanitor jout(ret);

    Transaction t;

    DDF tlist = in["tokens"];
    DDF token = tlist.first();
    while (token.isstring()) {
        // Parse and bind the document into an XMLObject.
        istringstream instr(token.string());
        DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(instr);
        XercesJanitor<DOMDocument> janitor(doc);
        XMLObject* xmlObject = XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true);
        t.tokens.push_back(xmlObject);
        janitor.release();
        token = tlist.next();
    }

    DDF alist = in["attributes"];
    Attribute* attribute;
    DDF attr = alist.first();
    while (!attr.isnull()) {
        attribute = Attribute::unmarshall(attr);
        t.inputAttrs.push_back(attribute);
        if (log.isDebugEnabled())
            log.debug("unmarshalled attribute (ID: %s) with %d value%s",
                attribute->getId(), attr.first().integer(), attr.first().integer()!=1 ? "s" : "");
        attr = alist.next();
    }

    auto_ptr_XMLCh prot(in["protocol"].string());

    resolve(*app, in["issuer"].string(), prot.get(), t.tokens, t.inputAttrs, t.resolvedAttrs);

    if (!t.resolvedAttrs.empty()) {
        ret.list();
        for (vector<Attribute*>::const_iterator a = t.resolvedAttrs.begin(); a != t.resolvedAttrs.end(); ++a) {
            attr = (*a)->marshall();
            ret.add(attr);
        }
    }

    out << ret;
}

void RemotedResolver::resolve(
    const Application& app,
    const char* issuer,
    const XMLCh* protocol,
    const vector<const XMLObject*>& tokens,
    const vector<Attribute*>& inputAttrs,
    vector<Attribute*>& resolvedAttrs
    ) const
{
#ifndef SHIBSP_LITE
    Category& log = Category::getInstance(SHIBRESOLVER_LOGCAT);
    MetadataProvider* m = app.getMetadataProvider(false);
    Locker locker(m);

    const RoleDescriptor* role = NULL;
    if (issuer && *issuer)
        role = lookup(app, m, issuer, protocol);

    vector<const Assertion*> assertions;

    AttributeExtractor* extractor = app.getAttributeExtractor();
    if (extractor) {
        Locker extlocker(extractor);
        // Support metadata-based attributes for only the "top-level" issuer.
        if (role) {
            pair<bool,const char*> mprefix = app.getString("metadataAttributePrefix");
            if (mprefix.first) {
                log.debug("extracting metadata-derived attributes...");
                try {
                    // We pass NULL for "issuer" because the issuer isn't the one asserting metadata-based attributes.
                    extractor->extractAttributes(app, NULL, *role, resolvedAttrs);
                    for (vector<Attribute*>::iterator a = resolvedAttrs.begin(); a != resolvedAttrs.end(); ++a) {
                        vector<string>& ids = (*a)->getAliases();
                        for (vector<string>::iterator id = ids.begin(); id != ids.end(); ++id)
                            *id = mprefix.second + *id;
                    }
                }
                catch (exception& ex) {
                    log.error("caught exception extracting attributes: %s", ex.what());
                }
            }
        }

        log.debug("extracting pushed attributes...");
        const RoleDescriptor* role2;
        for (vector<const XMLObject*>::const_iterator t = tokens.begin(); t != tokens.end(); ++t) {
            // Save off any assertions for later use by resolver.
            role2 = NULL;
            const Assertion* assertion = dynamic_cast<const Assertion*>(*t);
            if (assertion) {
                assertions.push_back(assertion);
                const saml2::Assertion* saml2token = dynamic_cast<const saml2::Assertion*>(assertion);
                if (saml2token && saml2token->getIssuer() && (saml2token->getIssuer()->getFormat() == NULL ||
                        XMLString::equals(saml2token->getIssuer()->getFormat(), saml2::NameID::ENTITY))) {
                    auto_ptr_char tokenissuer(saml2token->getIssuer()->getName());
                    role2 = lookup(app, m, tokenissuer.get(), protocol);
                }
            }
            resolve(extractor, app, (role2 ? role2 : role), *(*t), resolvedAttrs);
        }
    }
    else {
        log.warn("no AttributeExtractor plugin installed, check log during startup");
    }

    try {
        AttributeResolver* resolver = app.getAttributeResolver();
        if (resolver) {
            log.debug("resolving additional attributes...");

            vector<Attribute*> inputs = inputAttrs;
            inputs.insert(inputs.end(), resolvedAttrs.begin(), resolvedAttrs.end());

            Locker locker(resolver);
            auto_ptr<ResolutionContext> ctx(
                resolver->createResolutionContext(
                    app,
                    role ? dynamic_cast<const EntityDescriptor*>(role->getParent()) : NULL,
                    protocol ? protocol : samlconstants::SAML20P_NS,
                    NULL,
                    NULL,
                    NULL,
                    &assertions,
                    &inputs
                    )
                );
            resolver->resolveAttributes(*ctx.get());
            if (!ctx->getResolvedAttributes().empty())
                resolvedAttrs.insert(resolvedAttrs.end(), ctx->getResolvedAttributes().begin(), ctx->getResolvedAttributes().end());
        }
    }
    catch (exception& ex) {
        log.error("attribute resolution failed: %s", ex.what());
    }
#else
    throw ConfigurationException("Cannot process request using lite version of shibsp library.");
#endif
}

#ifndef SHIBSP_LITE

void RemotedResolver::resolve(
    AttributeExtractor* extractor,
    const Application& app,
    const RoleDescriptor* issuer,
    const XMLObject& token,
    vector<Attribute*>& resolvedAttrs
    ) const
{
    vector<Attribute*> extractedAttrs;
    try {
        extractor->extractAttributes(app, issuer, token, extractedAttrs);
    }
    catch (exception& ex) {
        Category::getInstance(SHIBRESOLVER_LOGCAT).error("caught exception extracting attributes: %s", ex.what());
    }

    AttributeFilter* filter = app.getAttributeFilter();
    if (filter && !extractedAttrs.empty()) {
        BasicFilteringContext fc(app, extractedAttrs, issuer);
        Locker filtlocker(filter);
        try {
            filter->filterAttributes(fc, extractedAttrs);
        }
        catch (exception& ex) {
            Category::getInstance(SHIBRESOLVER_LOGCAT).error("caught exception filtering attributes: %s", ex.what());
            Category::getInstance(SHIBRESOLVER_LOGCAT).error("dumping extracted attributes due to filtering exception");
            for_each(extractedAttrs.begin(), extractedAttrs.end(), xmltooling::cleanup<shibsp::Attribute>());
            extractedAttrs.clear();
        }
    }

    resolvedAttrs.insert(resolvedAttrs.end(), extractedAttrs.begin(), extractedAttrs.end());
}

const RoleDescriptor* RemotedResolver::lookup(
    const Application& app, MetadataProvider* m, const char* entityID, const XMLCh* protocol
    ) const
{
    if (!m)
        return NULL;

    MetadataProviderCriteria idpmc(app, entityID, &IDPSSODescriptor::ELEMENT_QNAME, protocol ? protocol : samlconstants::SAML20P_NS);
    if (protocol)
        idpmc.protocol2 = samlconstants::SAML20P_NS;
    pair<const EntityDescriptor*,const RoleDescriptor*> entity = m->getEntityDescriptor(idpmc);
    if (!entity.first) {
        Category::getInstance(SHIBRESOLVER_LOGCAT).warn("unable to locate metadata for provider (%s)", entityID);
    }
    else if (!entity.second) {
        MetadataProviderCriteria aamc(
            app, entityID, &AttributeAuthorityDescriptor::ELEMENT_QNAME, protocol ? protocol : samlconstants::SAML20P_NS
            );
        if (protocol)
            aamc.protocol2 = samlconstants::SAML20P_NS;
        entity = m->getEntityDescriptor(aamc);
        if (!entity.second) {
            Category::getInstance(SHIBRESOLVER_LOGCAT).warn("unable to locate compatible IdP or AA role for provider (%s)", entityID);
        }
    }

    return entity.second;
}

#endif

bool ShibbolethResolver::init(unsigned long features, const char* config, bool rethrow)
{
    if (features && SPConfig::OutOfProcess) {
#ifndef SHIBSP_LITE
        features = features | SPConfig::AttributeResolution | SPConfig::Metadata | SPConfig::Trust | SPConfig::Credentials;
#endif
        if (!(features && SPConfig::InProcess))
            features |= SPConfig::Listener;
    }
    else if (features && SPConfig::InProcess) {
        features |= SPConfig::Listener;
    }
    SPConfig::getConfig().setFeatures(features);
    if (!SPConfig::getConfig().init())
        return false;
    if (!SPConfig::getConfig().instantiate(config, rethrow))
        return false;
    return true;
}

/**
    * Shuts down runtime.
    *
    * Each process using the library SHOULD call this function exactly once before terminating itself.
    */
void ShibbolethResolver::term()
{
    SPConfig::getConfig().term();
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
