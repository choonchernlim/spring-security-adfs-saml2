package com.github.choonchernlim.security.adfs.saml2;

import static com.github.choonchernlim.betterPreconditions.preconditions.PreconditionFactory.expect;
import com.google.common.base.Splitter;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jndi.JndiTemplate;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Iterator;
import java.util.List;

/**
 * Helper class that retrieves JNDI value and returns a keystore bean.
 * The JNDI value has the following format: "jks-path,alias,storepass,keypass"
 */
public class JndiBackedKeystoreService {
    private final ResourceLoader resourceLoader = new DefaultResourceLoader();

    /**
     * JNDI name
     */
    private final String jndiName;

    private JndiTemplate jndiTemplate = new JndiTemplate();

    public JndiBackedKeystoreService(final String jndiName) {
        this.jndiName = jndiName;
    }

    /**
     * For mocking out instance during testing.
     *
     * @param jndiTemplate Jndi template
     */
    public void setJndiTemplate(final JndiTemplate jndiTemplate) {
        this.jndiTemplate = jndiTemplate;
    }

    /**
     * Retrieves keystore info from JNDI.
     *
     * @return Keystore bean
     */
    public KeystoreBean get() {
        final Iterator<String> ite = getJndiValues();
        return getKeystoreBean(ite.next(), ite.next(), ite.next(), ite.next());
    }

    /**
     * Returns transformed JNDI value from comma separated value to collection.
     *
     * @return JNDI values
     */
    private Iterator<String> getJndiValues() {
        final String jndiValue;
        try {
            jndiValue = jndiTemplate.lookup("java:comp/env/" + jndiName, String.class);
        }
        catch (Exception e) {
            throw new SpringSecurityAdfsSaml2Exception(String.format("Unable to get value from JNDI: %s", jndiName), e);
        }

        final List<String> jndiValues = Splitter.on(",").trimResults().splitToList(jndiValue);

        expect(jndiValues.size(), "jndiValues size").toBeEqual(4).check();

        return jndiValues.iterator();
    }

    /**
     * Ensures the input values are all valid before returning keystore bean.
     *
     * @param jksPath                    JKS path
     * @param keystoreAlias              Keystore alias
     * @param keystorePassword           Keystore password
     * @param keystorePrivateKeyPassword Keystore private key password
     * @return Keystore bean
     */
    private KeystoreBean getKeystoreBean(final String jksPath,
                                         final String keystoreAlias,
                                         final String keystorePassword,
                                         final String keystorePrivateKeyPassword) {
        final Resource keystoreResource = resourceLoader.getResource(jksPath);

        final InputStream keystoreInputStream;
        try {
            keystoreInputStream = keystoreResource.getInputStream();
        }
        catch (Exception e) {
            throw new SpringSecurityAdfsSaml2Exception("Invalid keystore path", e);
        }

        final KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        }
        catch (Exception e) {
            throw new SpringSecurityAdfsSaml2Exception("Unable to initialize keystore", e);
        }

        try {
            keyStore.load(keystoreInputStream, keystorePassword.toCharArray());
        }
        catch (Exception e) {
            throw new SpringSecurityAdfsSaml2Exception("Invalid keystore password", e);
        }

        try {
            if (!keyStore.isKeyEntry(keystoreAlias)) {
                throw new IllegalArgumentException("Provided alias not found");
            }
        }
        catch (Exception e) {
            throw new SpringSecurityAdfsSaml2Exception("Invalid keystore alias", e);
        }

        try {
            keyStore.getKey(keystoreAlias, keystorePrivateKeyPassword.toCharArray());
        }
        catch (Exception e) {
            throw new SpringSecurityAdfsSaml2Exception("Invalid keystore private key password", e);
        }

        return new KeystoreBeanBuilder()
                .withJksPath(jksPath)
                .withKeystoreAlias(keystoreAlias)
                .withKeystorePassword(keystorePassword)
                .withKeystorePrivateKeyPassword(keystorePrivateKeyPassword)
                .withKeystoreResource(keystoreResource)
                .build();
    }


}
