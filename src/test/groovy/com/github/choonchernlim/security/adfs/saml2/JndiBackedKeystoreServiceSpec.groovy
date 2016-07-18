package com.github.choonchernlim.security.adfs.saml2

import com.github.choonchernlim.betterPreconditions.exception.NumberNotEqualPreconditionException
import org.springframework.mock.jndi.ExpectedLookupTemplate
import spock.lang.Specification
import spock.lang.Unroll

class JndiBackedKeystoreServiceSpec extends Specification {

    def jndiName = 'jks/idm'
    def jndiLookupValue = "java:comp/env/${jndiName}"

    def "given invalid jndi name, should throw exception"() {
        given:
        def service = new JndiBackedKeystoreService('jks/invalid')
        service.setJndiTemplate(new ExpectedLookupTemplate(jndiLookupValue, 'bla'))

        when:
        service.get()

        then:
        thrown SpringSecurityAdfsSaml2Exception
    }

    @Unroll
    def "given invalid jndi value ( #jndiValue ), should throw exception"() {
        given:
        def service = new JndiBackedKeystoreService(jndiName)
        service.setJndiTemplate(new ExpectedLookupTemplate(jndiLookupValue, jndiValue))

        when:
        service.get()

        then:
        thrown expectedException

        where:
        jndiValue                                                   | expectedException
        'classpath:test.jks,test,test-storepass,test-keypass,extra' | NumberNotEqualPreconditionException
        'classpath:test.jks,test,test-storepass'                    | NumberNotEqualPreconditionException
        'classpath:invalid.jks,test,test-storepass,test-keypass'    | SpringSecurityAdfsSaml2Exception
        'classpath:test.jks,invalid,test-storepass,test-keypass'    | SpringSecurityAdfsSaml2Exception
        'classpath:test.jks,test,invalid-storepass,test-keypass'    | SpringSecurityAdfsSaml2Exception
        'classpath:test.jks,test,test-storepass,invalid-keypass'    | SpringSecurityAdfsSaml2Exception
    }

    def "given valid jndi value, should return keystore bean"() {
        given:
        def service = new JndiBackedKeystoreService(jndiName)
        def jndiValue = 'classpath:test.jks,test,test-storepass,test-keypass'
        service.setJndiTemplate(new ExpectedLookupTemplate(jndiLookupValue, jndiValue))

        when:
        def bean = service.get()

        then:
        bean.jksPath == 'classpath:test.jks'
        bean.keystoreAlias == 'test'
        bean.keystorePassword == 'test-storepass'
        bean.keystorePrivateKeyPassword == 'test-keypass'
        bean.keystoreResource.exists()
    }
}
