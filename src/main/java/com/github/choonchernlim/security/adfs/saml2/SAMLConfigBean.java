package com.github.choonchernlim.security.adfs.saml2;

import static com.github.choonchernlim.betterPreconditions.preconditions.PreconditionFactory.expect;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableSet;
import org.opensaml.saml2.core.AuthnContext;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import java.util.Set;

/**
 * This class contains all properties that can be configured by Sp using the provided builder class.
 */
public final class SAMLConfigBean {

    /**
     * (REQUIRED) ADFS host name without HTTPS protocol.
     */
    private final String adfsHostName;

    /**
     * (REQUIRED) Keystore containing app's public/private key and ADFS' certificate with public key.
     */
    private final Resource keyStoreResource;

    /**
     * (REQUIRED) Keystore alias.
     */
    private final String keystoreAlias;

    /**
     * (REQUIRED) Keystore password.
     */
    private final String keystorePassword;

    /**
     * (REQUIRED) Where to redirect user on successful login if no saved request is found in the session.
     */
    private final String successLoginDefaultUrl;

    /**
     * (REQUIRED) Where to redirect user on successful logout.
     */
    private final String successLogoutUrl;

    /**
     * Where to redirect user on failed login. This value is set to null, which returns
     * 401 error code on failed login. But, in theory, this will never be used because
     * IdP will handled the failed login on IdP login page.
     * <p/>
     * Default is blank.
     */
    private final String failedLoginDefaultUrl;

    /**
     * For configuring user authorities if needed.
     * <p/>
     * Default is null.
     */
    private final SAMLUserDetailsService samlUserDetailsService;

    /**
     * Determine what authentication methods to use.
     * <p/>
     * To use the order of authentication methods defined by IdP, set as empty set.
     * <p/>
     * To enable Windows Integrated Auth (WIA) cross browsers and OSes, use `CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX`.
     * <p/>
     * Default is user/password authentication where IdP login page is displayed.
     */
    private final Set<String> authnContexts;

    SAMLConfigBean(final String adfsHostName,
                   final Resource keyStoreResource,
                   final String keystoreAlias,
                   final String keystorePassword,
                   final String successLoginDefaultUrl,
                   final String successLogoutUrl,
                   final String failedLoginDefaultUrl,
                   final SAMLUserDetailsService samlUserDetailsService,
                   final Set<String> authnContexts) {

        this.adfsHostName = expect(adfsHostName, "ADFS host name").not().toBeBlank().check();

        this.keyStoreResource = (Resource) expect(keyStoreResource, "Key store").not().toBeNull().check();
        this.keystoreAlias = expect(keystoreAlias, "Keystore alias").not().toBeBlank().check();
        this.keystorePassword = expect(keystorePassword, "Keystore password").not().toBeBlank().check();

        this.successLoginDefaultUrl = expect(successLoginDefaultUrl, "Success login URL").not().toBeBlank().check();
        this.successLogoutUrl = expect(successLogoutUrl, "Success logout URL").not().toBeBlank().check();

        this.failedLoginDefaultUrl = Optional.fromNullable(failedLoginDefaultUrl).or("");

        this.samlUserDetailsService = samlUserDetailsService;

        this.authnContexts = Optional.fromNullable(authnContexts).or(ImmutableSet.of(AuthnContext.PASSWORD_AUTHN_CTX));
    }

    public String getAdfsHostName() {
        return adfsHostName;
    }

    public Resource getKeyStoreResource() {
        return keyStoreResource;
    }

    public String getKeystoreAlias() {
        return keystoreAlias;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getSuccessLoginDefaultUrl() {
        return successLoginDefaultUrl;
    }

    public String getSuccessLogoutUrl() {
        return successLogoutUrl;
    }

    public String getFailedLoginDefaultUrl() {
        return failedLoginDefaultUrl;
    }

    public SAMLUserDetailsService getSamlUserDetailsService() {
        return samlUserDetailsService;
    }

    public Set<String> getAuthnContexts() {
        return authnContexts;
    }
}
