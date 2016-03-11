package com.github.choonchernlim.security.adfs.saml2

import com.github.choonchernlim.betterPreconditions.exception.ObjectNullPreconditionException
import com.github.choonchernlim.betterPreconditions.exception.StringBlankPreconditionException
import org.opensaml.saml2.core.AuthnContext
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.userdetails.SAMLUserDetailsService
import spock.lang.Specification
import spock.lang.Unroll

class SAMLConfigBeanSpec extends Specification {

    def keystoreResource = new DefaultResourceLoader().getResource("classpath:keystore.jks")

    def samlUserDetailsService = new SAMLUserDetailsService() {
        @Override
        Object loadUserBySAML(final SAMLCredential credential) throws UsernameNotFoundException {
            return new User('limc', '', [new SimpleGrantedAuthority('ROLE_USER')])
        }
    }
    def allFieldsBeanBuilder = new SAMLConfigBeanBuilder().
            setSpMetadataBaseUrl('spMetadataBaseUrl').
            setAdfsHostName('adfsHostName').
            setKeystoreResource(keystoreResource).
            setKeystoreAlias('keystoreAlias').
            setKeystorePassword('keystorePassword').
            setKeystorePrivateKeyPassword('keystorePrivateKeyPassword').
            setSuccessLoginDefaultUrl('successLoginDefaultUrl').
            setSuccessLogoutUrl('successLogoutUrl').
            setFailedLoginDefaultUrl('failedLoginDefaultUrl').
            setSamlUserDetailsService(samlUserDetailsService).
            setAuthnContexts([CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX] as Set)

    def "required and optional fields"() {
        when:
        def bean = allFieldsBeanBuilder.createSAMLConfigBean()

        then:
        bean.spMetadataBaseUrl == 'spMetadataBaseUrl'
        bean.adfsHostName == 'adfsHostName'
        bean.keystoreResource == keystoreResource
        bean.keystoreAlias == 'keystoreAlias'
        bean.keystorePassword == 'keystorePassword'
        bean.keystorePrivateKeyPassword == 'keystorePrivateKeyPassword'
        bean.successLoginDefaultUrl == 'successLoginDefaultUrl'
        bean.successLogoutUrl == 'successLogoutUrl'
        bean.failedLoginDefaultUrl == 'failedLoginDefaultUrl'
        bean.samlUserDetailsService == samlUserDetailsService
        bean.authnContexts == [CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX] as Set
    }

    def "only required fields"() {
        when:
        def bean = allFieldsBeanBuilder.
                setFailedLoginDefaultUrl(null).
                setSamlUserDetailsService(null).
                setAuthnContexts(null).
                createSAMLConfigBean()

        then:
        bean.spMetadataBaseUrl == 'spMetadataBaseUrl'
        bean.adfsHostName == 'adfsHostName'
        bean.keystoreResource == keystoreResource
        bean.keystoreAlias == 'keystoreAlias'
        bean.keystorePassword == 'keystorePassword'
        bean.keystorePrivateKeyPassword == 'keystorePrivateKeyPassword'
        bean.successLoginDefaultUrl == 'successLoginDefaultUrl'
        bean.successLogoutUrl == 'successLogoutUrl'
        bean.failedLoginDefaultUrl == ''
        bean.samlUserDetailsService == null
        bean.authnContexts == [AuthnContext.PASSWORD_AUTHN_CTX] as Set
    }

    def "authnContexts - empty set is fine"() {
        when:
        def bean = allFieldsBeanBuilder.
                setAuthnContexts([] as Set).
                createSAMLConfigBean()

        then:
        bean.authnContexts == [] as Set
    }

    @Unroll
    def "missing required field - #field"() {
        when:
        allFieldsBeanBuilder."set$field"(null).createSAMLConfigBean()

        then:
        thrown expectedException

        where:
        field                        | expectedException
        'SpMetadataBaseUrl'          | StringBlankPreconditionException
        'AdfsHostName'               | StringBlankPreconditionException
        'KeystoreResource'           | ObjectNullPreconditionException
        'KeystoreAlias'              | StringBlankPreconditionException
        'KeystorePassword'           | StringBlankPreconditionException
        'KeystorePrivateKeyPassword' | StringBlankPreconditionException
        'SuccessLoginDefaultUrl'     | StringBlankPreconditionException
        'SuccessLogoutUrl'           | StringBlankPreconditionException
    }

}
