package com.github.choonchernlim.security.adfs.saml2

import spock.lang.Specification

class SpringSecurityAdfsSaml2ExceptionSpec extends Specification {

    def "exception"() {
        when:
        def exception = new SpringSecurityAdfsSaml2Exception('test')

        then:
        exception instanceof RuntimeException
        exception.message == 'test'
    }
}
