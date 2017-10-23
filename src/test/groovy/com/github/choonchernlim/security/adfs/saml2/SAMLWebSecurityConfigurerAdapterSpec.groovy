package com.github.choonchernlim.security.adfs.saml2

import com.github.choonchernlim.betterPreconditions.exception.ObjectNullPreconditionException
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.userdetails.SAMLUserDetailsService
import spock.lang.Specification
import spock.lang.Unroll

class SAMLWebSecurityConfigurerAdapterSpec extends Specification {
    private static final String ALIAS = 'test'
    private static final String STOREPASS = 'test-storepass'
    private static final String KEYPASS = 'test-keypass'

    def keystoreResource = new DefaultResourceLoader().getResource("classpath:test.jks")

    static def samlUserDetailsService = new SAMLUserDetailsService() {
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
            withKeystoreAlias(ALIAS).
            withKeystorePassword(STOREPASS).
            withKeystorePrivateKeyPassword(KEYPASS).
            withSuccessLoginDefaultUrl('successLoginDefaultUrl').
            withSuccessLogoutUrl('successLogoutUrl').
            withFailedLoginDefaultUrl('failedLoginDefaultUrl').
            withSamlUserDetailsService(samlUserDetailsService).
            withAuthnContexts([CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX] as Set)

    @Unroll
    @SuppressWarnings("all")
    def "metadataGeneratorFilter - entityBaseURL - #expectedValue"() {
        given:
        def samlConfigBean = allFieldsBeanBuilder.
                withSpServerName(server).
                withSpHttpsPort(port).
                withSpContextPath(contextPath).
                build()

        when:
        def adapter = new SAMLWebSecurityConfigurerAdapter() {
            @Override
            protected SAMLConfigBean samlConfigBean() {
                return samlConfigBean
            }
        }

        then:
        expectedValue == adapter.metadataGeneratorFilter().generator.entityBaseURL

        where:
        server   | port | contextPath | expectedValue
        'server' | null | null        | 'https://server'
        'server' | 443  | null        | 'https://server'
        'server' | 443  | '/app'      | 'https://server/app'
        'server' | 8443 | null        | 'https://server:8443'
        'server' | 8443 | '/app'      | 'https://server:8443/app'
    }

    @Unroll
    @SuppressWarnings("all")
    def "contextProvider - #expectedValue"() {
        given:
        def samlConfigBean = allFieldsBeanBuilder.
                withSpServerName(aServer).
                withSpHttpsPort(aPort).
                withSpContextPath(aContextPath).
                build()

        when:
        def adapter = new SAMLWebSecurityConfigurerAdapter() {
            @Override
            protected SAMLConfigBean samlConfigBean() {
                return samlConfigBean
            }
        }

        then:
        with(adapter.contextProvider()) {
            scheme == 'https'
            serverName == aServer
            serverPort == ePort
            contextPath == eContextPath
            includeServerPortInRequestURL == ePortIncluded
        }

        where:
        aServer  | aPort | aContextPath | ePort | ePortIncluded | eContextPath | expectedValue
        'server' | null  | null         | 443   | false         | ''           | 'https://server'
        'server' | 443   | null         | 443   | false         | ''           | 'https://server'
        'server' | 443   | '/app'       | 443   | false         | '/app'       | 'https://server/app'
        'server' | 8443  | null         | 8443  | true          | ''           | 'https://server:8443'
        'server' | 8443  | '/app'       | 8443  | true          | '/app'       | 'https://server:8443/app'
    }

    @Unroll
    def "authenticationProvider - given samlUserDetailsService as #actualSamlUserDetailsService, then forcePrincipalAsString should be #expectedForcePrincipalAsString"() {
        given:
        SAMLUserDetailsService userDetailsService = actualSamlUserDetailsService

        when:
        def adapter = new SAMLWebSecurityConfigurerAdapter() {
            @Override
            protected SAMLConfigBean samlConfigBean() {
                return allFieldsBeanBuilder.
                        withSamlUserDetailsService(userDetailsService).
                        build()
            }
        }

        then:
        expectedForcePrincipalAsString == adapter.samlAuthenticationProvider().forcePrincipalAsString

        where:
        actualSamlUserDetailsService | expectedForcePrincipalAsString
        null                         | true
        samlUserDetailsService       | false
    }

    def "authenticationProvider caches the result, returns same one on multiple calls"() {
        given:
        SAMLUserDetailsService userDetailsService = samlUserDetailsService

        when:
        def adapter = new SAMLWebSecurityConfigurerAdapter() {
            @Override
            protected SAMLConfigBean samlConfigBean() {
                return allFieldsBeanBuilder.
                        withSamlUserDetailsService(userDetailsService).
                        build()
            }
        }

        def provider1 = adapter.samlAuthenticationProvider()
        def provider2 = adapter.samlAuthenticationProvider()

        then:
        provider1 == provider2
    }

    def "mockSecurity - given null user, should throw exception"() {
        given:
        def http = new HttpSecurity(Mock(ObjectPostProcessor), Mock(AuthenticationManagerBuilder), [:] as Map)

        def adapter = new SAMLWebSecurityConfigurerAdapter() {
            @Override
            protected SAMLConfigBean samlConfigBean() {
                return allFieldsBeanBuilder.build()
            }
        }

        when:
        adapter.mockSecurity(http, null)

        then:
        thrown ObjectNullPreconditionException
    }

    def "mockSecurity - given null samlUserDetailsService, should throw exception"() {
        given:
        def http = new HttpSecurity(Mock(ObjectPostProcessor), Mock(AuthenticationManagerBuilder), [:] as Map)

        def adapter = new SAMLWebSecurityConfigurerAdapter() {
            @Override
            protected SAMLConfigBean samlConfigBean() {
                return allFieldsBeanBuilder.withSamlUserDetailsService(null).build()
            }
        }

        when:
        adapter.mockSecurity(http, new User('USER', '', []))

        then:
        thrown SpringSecurityAdfsSaml2Exception
    }

    def "mockSecurity - given user and samlUserDetailsService, should not throw exception"() {
        given:
        def http = new HttpSecurity(Mock(ObjectPostProcessor), Mock(AuthenticationManagerBuilder), [:] as Map)

        def adapter = new SAMLWebSecurityConfigurerAdapter() {
            @Override
            protected SAMLConfigBean samlConfigBean() {
                return allFieldsBeanBuilder.build()
            }
        }

        when:
        adapter.mockSecurity(http, new User('USER', '', []))

        then:
        notThrown Exception
    }
}
