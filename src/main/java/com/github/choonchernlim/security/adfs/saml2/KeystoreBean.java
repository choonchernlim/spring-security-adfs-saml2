package com.github.choonchernlim.security.adfs.saml2;

import net.karneim.pojobuilder.GeneratePojoBuilder;
import org.springframework.core.io.Resource;

/**
 * Keystore related info.
 */
public final class KeystoreBean {
    private final String jksPath;
    private final String keystoreAlias;
    private final String keystorePassword;
    private final String keystorePrivateKeyPassword;
    private final Resource keystoreResource;

    @GeneratePojoBuilder
    KeystoreBean(final String jksPath,
                 final String keystoreAlias,
                 final String keystorePassword,
                 final String keystorePrivateKeyPassword,
                 final Resource keystoreResource) {
        this.jksPath = jksPath;
        this.keystoreAlias = keystoreAlias;
        this.keystorePassword = keystorePassword;
        this.keystorePrivateKeyPassword = keystorePrivateKeyPassword;
        this.keystoreResource = keystoreResource;
    }

    public String getJksPath() {
        return jksPath;
    }

    public String getKeystoreAlias() {
        return keystoreAlias;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getKeystorePrivateKeyPassword() {
        return keystorePrivateKeyPassword;
    }

    public Resource getKeystoreResource() {
        return keystoreResource;
    }
}
