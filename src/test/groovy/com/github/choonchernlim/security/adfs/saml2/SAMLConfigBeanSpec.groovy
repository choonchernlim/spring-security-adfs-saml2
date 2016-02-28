package com.github.choonchernlim.security.adfs.saml2

import com.github.choonchernlim.betterPreconditions.exception.ObjectNullPreconditionException
import com.github.choonchernlim.betterPreconditions.exception.StringBlankPreconditionException
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
            setAdfsHostName('adfsHostName').
            setKeyStoreResource(keystoreResource).
            setKeystoreAlias('keystoreAlias').
            setKeystorePassword('keystorePassword').
            setSuccessLoginDefaultUrl('successLoginDefaultUrl').
            setSuccessLogoutUrl('successLogoutUrl').
            setFailedLoginDefaultUrl('failedLoginDefaultUrl').
            setSamlUserDetailsService(samlUserDetailsService)

    def "required and optional fields"() {
        when:
        def bean = allFieldsBeanBuilder.createSAMLConfigBean()

        then:
        bean.adfsHostName == 'adfsHostName'
        bean.keyStoreResource == keystoreResource
        bean.keystoreAlias == 'keystoreAlias'
        bean.keystorePassword == 'keystorePassword'
        bean.successLoginDefaultUrl == 'successLoginDefaultUrl'
        bean.successLogoutUrl == 'successLogoutUrl'
        bean.failedLoginDefaultUrl == 'failedLoginDefaultUrl'
        bean.samlUserDetailsService == samlUserDetailsService
    }

    def "only required fields"() {
        when:
        def bean = allFieldsBeanBuilder.
                setFailedLoginDefaultUrl(null).
                setSamlUserDetailsService(null).
                createSAMLConfigBean()

        then:
        bean.adfsHostName == 'adfsHostName'
        bean.keyStoreResource == keystoreResource
        bean.keystoreAlias == 'keystoreAlias'
        bean.keystorePassword == 'keystorePassword'
        bean.successLoginDefaultUrl == 'successLoginDefaultUrl'
        bean.successLogoutUrl == 'successLogoutUrl'
        bean.failedLoginDefaultUrl == ''
        bean.samlUserDetailsService == null
    }

    @Unroll
    def "missing required field - #field"() {
        when:
        allFieldsBeanBuilder."set$field"(null).createSAMLConfigBean()

        then:
        thrown expectedException

        where:
        field                    | expectedException
        'AdfsHostName'           | StringBlankPreconditionException
        'KeyStoreResource'       | ObjectNullPreconditionException
        'KeystoreAlias'          | StringBlankPreconditionException
        'KeystorePassword'       | StringBlankPreconditionException
        'SuccessLoginDefaultUrl' | StringBlankPreconditionException
        'SuccessLogoutUrl'       | StringBlankPreconditionException
    }

}
