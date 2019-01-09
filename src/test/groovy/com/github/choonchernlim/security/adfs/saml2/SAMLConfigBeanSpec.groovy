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
            withIdpServerName('idpServerName').
            withSpServerName('spServerName').
            withSpHttpsPort(8443).
            withSpContextPath('spContextPath').
            withKeystoreResource(keystoreResource).
            withKeystoreAlias('keystoreAlias').
            withKeystorePassword('keystorePassword').
            withKeystorePrivateKeyPassword('keystorePrivateKeyPassword').
            withSuccessLoginDefaultUrl('successLoginDefaultUrl').
            withSuccessLogoutUrl('successLogoutUrl').
            withFailedLoginDefaultUrl('failedLoginDefaultUrl').
            withStoreCsrfTokenInCookie(true).
            withSamlUserDetailsService(samlUserDetailsService).
            withAuthnContexts([CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX] as Set).
            withUseJdkCacertsForSslVerification(true)

    def "required and optional fields"() {
        when:
        def bean = allFieldsBeanBuilder.build()

        then:
        bean.idpServerName == 'idpServerName'
        bean.spServerName == 'spServerName'
        bean.spHttpsPort == 8443
        bean.spContextPath == 'spContextPath'
        bean.keystoreResource == keystoreResource
        bean.keystoreAlias == 'keystoreAlias'
        bean.keystorePassword == 'keystorePassword'
        bean.keystorePrivateKeyPassword == 'keystorePrivateKeyPassword'
        bean.successLoginDefaultUrl == 'successLoginDefaultUrl'
        bean.successLogoutUrl == 'successLogoutUrl'
        bean.failedLoginDefaultUrl == 'failedLoginDefaultUrl'
        bean.storeCsrfTokenInCookie
        bean.samlUserDetailsService == samlUserDetailsService
        bean.authnContexts == [CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX] as Set
        bean.useJdkCacertsForSslVerification
    }

    def "only required fields"() {
        when:
        def bean = allFieldsBeanBuilder.
                withSpHttpsPort(null).
                withSpContextPath(null).
                withFailedLoginDefaultUrl(null).
                withSamlUserDetailsService(null).
                withAuthnContexts(null).
                withStoreCsrfTokenInCookie(null).
                withUseJdkCacertsForSslVerification(null).
                build()

        then:
        bean.idpServerName == 'idpServerName'
        bean.spServerName == 'spServerName'
        bean.spHttpsPort == 443
        bean.spContextPath == ''
        bean.keystoreResource == keystoreResource
        bean.keystoreAlias == 'keystoreAlias'
        bean.keystorePassword == 'keystorePassword'
        bean.keystorePrivateKeyPassword == 'keystorePrivateKeyPassword'
        bean.successLoginDefaultUrl == 'successLoginDefaultUrl'
        bean.successLogoutUrl == 'successLogoutUrl'
        bean.failedLoginDefaultUrl == ''
        !bean.storeCsrfTokenInCookie
        bean.samlUserDetailsService == null
        bean.authnContexts == [AuthnContext.PASSWORD_AUTHN_CTX] as Set
        !bean.useJdkCacertsForSslVerification
    }

    def "authnContexts - empty set is fine"() {
        when:
        def bean = allFieldsBeanBuilder.
                withAuthnContexts([] as Set).
                build()

        then:
        bean.authnContexts == [] as Set
    }

    @Unroll
    def "missing required field - #field"() {
        when:
        allFieldsBeanBuilder."with$field"(null).build()

        then:
        thrown expectedException

        where:
        field                        | expectedException
        'IdpServerName'              | StringBlankPreconditionException
        'SpServerName'               | StringBlankPreconditionException
        'KeystoreResource'           | ObjectNullPreconditionException
        'KeystoreAlias'              | StringBlankPreconditionException
        'KeystorePassword'           | StringBlankPreconditionException
        'KeystorePrivateKeyPassword' | StringBlankPreconditionException
        'SuccessLoginDefaultUrl'     | StringBlankPreconditionException
        'SuccessLogoutUrl'           | StringBlankPreconditionException
    }

}
