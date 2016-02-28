package com.github.choonchernlim.security.adfs.saml2

import org.opensaml.Configuration
import org.opensaml.xml.security.BasicSecurityConfiguration
import org.opensaml.xml.signature.SignatureConstants
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.security.saml.SAMLBootstrap
import spock.lang.Specification

class DefaultSAMLBootstrapSpec extends Specification {

    def beanFactory = Mock ConfigurableListableBeanFactory

    def getConfig(def samlBootstrap) {
        samlBootstrap.postProcessBeanFactory(beanFactory)
        return (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration()
    }

    def "SAMLBootstrap - Spring provided implementation, for comparison reason"() {
        when:
        def config = getConfig(new SAMLBootstrap())

        then:
        config.getSignatureReferenceDigestMethod() == SignatureConstants.ALGO_ID_DIGEST_SHA1
        config.getSignatureAlgorithmURI('RSA') == SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1
    }

    def "DefaultSAMLBootstrap - no param"() {
        when:
        def config = getConfig(new DefaultSAMLBootstrap())

        then:
        config.getSignatureReferenceDigestMethod() == SignatureConstants.ALGO_ID_DIGEST_SHA256
        config.getSignatureAlgorithmURI('RSA') == SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256
    }

    def "DefaultSAMLBootstrap - with param"() {
        when:
        def config = getConfig(new DefaultSAMLBootstrap('RSA',
                                                        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512,
                                                        SignatureConstants.ALGO_ID_DIGEST_SHA512))

        then:
        config.getSignatureReferenceDigestMethod() == SignatureConstants.ALGO_ID_DIGEST_SHA512
        config.getSignatureAlgorithmURI('RSA') == SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512
    }


}
