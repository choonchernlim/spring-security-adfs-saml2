package com.github.choonchernlim.security.adfs.saml2

import com.github.choonchernlim.betterPreconditions.exception.ObjectNullPreconditionException
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import spock.lang.Specification

class MockFilterSecurityInterceptorSpec extends Specification {

    def request = new MockHttpServletRequest()
    def session = new MockHttpSession()
    def response = new MockHttpServletResponse()
    def chain = new MockFilterChain()

    def "setup"() {
        request.setSession(session)
    }

    def "given null user, should throw exception"() {
        when:
        new MockFilterSecurityInterceptor(null)

        then:
        thrown ObjectNullPreconditionException
    }

    def "given mock user, should be in security context and in session"() {
        given:
        def userAuthorities = [new SimpleGrantedAuthority('ROLE_USER')]
        def user = new User('RAMBO', '', userAuthorities)
        def filter = new MockFilterSecurityInterceptor(user)

        when:
        filter.doFilter(request, response, chain)

        then:
        def authentication = SecurityContextHolder.context.authentication

        with(authentication) {
            principal == user
            details == user
            credentials == null
            authorities == userAuthorities
        }

        authentication == (
                (SecurityContext) request.session.getAttribute(
                        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)
        ).authentication
    }

}
