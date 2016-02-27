package com.github.choonchernlim.security.adfs.saml2;

import static com.github.choonchernlim.betterPreconditions.preconditions.PreconditionFactory.expect;
import org.opensaml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.saml.SAMLBootstrap;

/**
 * By default, Spring Security SAML uses SHA1withRSA for signature algorithm and SHA-1 for digest algorithm.
 * <p/>
 * This class allows app to use stronger encryption such as SHA-256.
 * <p/>
 * See: http://stackoverflow.com/questions/23681362/how-to-change-the-signature-algorithm-of-saml-request-in-spring-security
 * See: http://stackoverflow.com/questions/25982093/setting-the-extendedmetadata-signingalgorithm-field/26004147
 */
public final class DefaultSAMLBootstrap extends SAMLBootstrap {

    private final String signatureAlgorithmName;
    private final String signatureAlgorithmURI;
    private final String digestAlgorithmURI;

    /**
     * Default signature algorithm is SHA256withRSA and default digest algorithm is SHA-256.
     */
    public DefaultSAMLBootstrap() {
        this("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA256);
    }

    /**
     * Allows user to specify different algorithm URIs.
     *
     * @param signatureAlgorithmName Signature algorithm name
     * @param signatureAlgorithmURI  Signature algorithm URI
     * @param digestAlgorithmURI     Digest algorithm URI
     */
    public DefaultSAMLBootstrap(final String signatureAlgorithmName,
                                final String signatureAlgorithmURI,
                                final String digestAlgorithmURI) {
        //@formatter:off
        this.signatureAlgorithmName = expect(signatureAlgorithmName, "Signature algorithm name").not().toBeBlank().check();
        this.signatureAlgorithmURI = expect(signatureAlgorithmURI, "Signature algorithm URI").not().toBeBlank().check();
        this.digestAlgorithmURI = expect(digestAlgorithmURI, "Digest algorithm URI").not().toBeBlank().check();
        //@formatter:on
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        super.postProcessBeanFactory(beanFactory);
        BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
        config.registerSignatureAlgorithmURI(signatureAlgorithmName, signatureAlgorithmURI);
        config.setSignatureReferenceDigestMethod(digestAlgorithmURI);
    }
}
