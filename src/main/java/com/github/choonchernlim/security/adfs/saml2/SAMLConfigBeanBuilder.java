package com.github.choonchernlim.security.adfs.saml2;

import org.springframework.core.io.Resource;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

public final class SAMLConfigBeanBuilder {
    private String adfsHostName;
    private Resource keyStoreResource;
    private String keystoreAlias;
    private String keystorePassword;
    private String successLoginDefaultUrl;
    private String successLogoutUrl;
    private String failedLoginDefaultUrl;
    private SAMLUserDetailsService userDetailsService;

    public SAMLConfigBeanBuilder setAdfsHostName(final String adfsHostName) {
        this.adfsHostName = adfsHostName;
        return this;
    }

    public SAMLConfigBeanBuilder setKeyStoreResource(final Resource keyStoreResource) {
        this.keyStoreResource = keyStoreResource;
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

    public SAMLConfigBeanBuilder setUserDetailsService(final SAMLUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
        return this;
    }

    public SAMLConfigBean createSAMLConfigBean() {
        return new SAMLConfigBean(adfsHostName,
                                  keyStoreResource,
                                  keystoreAlias,
                                  keystorePassword,
                                  successLoginDefaultUrl,
                                  successLogoutUrl,
                                  failedLoginDefaultUrl,
                                  userDetailsService);
    }
}