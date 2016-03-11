package com.github.choonchernlim.security.adfs.saml2;

import org.springframework.core.io.Resource;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import java.util.Set;

/**
 * Builder class for constructing SAMLConfigBean.
 */
public final class SAMLConfigBeanBuilder {
    private String spMetadataBaseUrl;
    private String adfsHostName;
    private Resource keystoreResource;
    private String keystoreAlias;
    private String keystorePassword;
    private String keystorePrivateKeyPassword;
    private String successLoginDefaultUrl;
    private String successLogoutUrl;
    private String failedLoginDefaultUrl;
    private SAMLUserDetailsService samlUserDetailsService;
    private Set<String> authnContexts;

    public SAMLConfigBeanBuilder setSpMetadataBaseUrl(final String spMetadataBaseUrl) {
        this.spMetadataBaseUrl = spMetadataBaseUrl;
        return this;
    }

    public SAMLConfigBeanBuilder setAdfsHostName(final String adfsHostName) {
        this.adfsHostName = adfsHostName;
        return this;
    }

    public SAMLConfigBeanBuilder setKeystoreResource(final Resource keystoreResource) {
        this.keystoreResource = keystoreResource;
        return this;
    }

    public SAMLConfigBeanBuilder setKeystoreAlias(final String keystoreAlias) {
        this.keystoreAlias = keystoreAlias;
        return this;
    }

    public SAMLConfigBeanBuilder setKeystorePassword(final String keystorePassword) {
        this.keystorePassword = keystorePassword;
        return this;
    }

    public SAMLConfigBeanBuilder setKeystorePrivateKeyPassword(final String keystorePrivateKeyPassword) {
        this.keystorePrivateKeyPassword = keystorePrivateKeyPassword;
        return this;
    }

    public SAMLConfigBeanBuilder setSuccessLoginDefaultUrl(final String successLoginDefaultUrl) {
        this.successLoginDefaultUrl = successLoginDefaultUrl;
        return this;
    }

    public SAMLConfigBeanBuilder setSuccessLogoutUrl(final String successLogoutUrl) {
        this.successLogoutUrl = successLogoutUrl;
        return this;
    }

    public SAMLConfigBeanBuilder setFailedLoginDefaultUrl(final String failedLoginDefaultUrl) {
        this.failedLoginDefaultUrl = failedLoginDefaultUrl;
        return this;
    }

    public SAMLConfigBeanBuilder setSamlUserDetailsService(final SAMLUserDetailsService samlUserDetailsService) {
        this.samlUserDetailsService = samlUserDetailsService;
        return this;
    }

    public SAMLConfigBeanBuilder setAuthnContexts(final Set<String> authnContexts) {
        this.authnContexts = authnContexts;
        return this;
    }

    public SAMLConfigBean createSAMLConfigBean() {
        return new SAMLConfigBean(spMetadataBaseUrl,
                                  adfsHostName,
                                  keystoreResource,
                                  keystoreAlias,
                                  keystorePassword,
                                  keystorePrivateKeyPassword,
                                  successLoginDefaultUrl,
                                  successLogoutUrl,
                                  failedLoginDefaultUrl,
                                  samlUserDetailsService,
                                  authnContexts);
    }
}