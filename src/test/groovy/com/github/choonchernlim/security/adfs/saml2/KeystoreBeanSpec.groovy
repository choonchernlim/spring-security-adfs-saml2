package com.github.choonchernlim.security.adfs.saml2

import org.springframework.core.io.DefaultResourceLoader
import spock.lang.Specification

class KeystoreBeanSpec extends Specification {

    def "give no params, should return default values"() {
        when:
        def bean = new KeystoreBeanBuilder().build()

        then:
        bean.jksPath == null
        bean.keystoreAlias == null
        bean.keystorePassword == null
        bean.keystorePrivateKeyPassword == null
        bean.keystoreResource == null
    }

    def "give with params, should return actual values"() {
        when:
        def bean = new KeystoreBeanBuilder().
                withJksPath('jksPath').
                withKeystoreAlias('keystoreAlias').
                withKeystorePassword('keystorePassword').
                withKeystorePrivateKeyPassword('keystorePrivateKeyPassword').
                withKeystoreResource(new DefaultResourceLoader().getResource('bla')).
                build()

        then:
        bean.jksPath == 'jksPath'
        bean.keystoreAlias == 'keystoreAlias'
        bean.keystorePassword == 'keystorePassword'
        bean.keystorePrivateKeyPassword == 'keystorePrivateKeyPassword'
        bean.keystoreResource != null
    }
}
