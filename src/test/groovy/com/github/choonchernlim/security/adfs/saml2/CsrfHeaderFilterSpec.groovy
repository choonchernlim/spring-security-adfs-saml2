package com.github.choonchernlim.security.adfs.saml2

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.security.web.csrf.DefaultCsrfToken
import spock.lang.Specification

import javax.servlet.http.Cookie

class CsrfHeaderFilterSpec extends Specification {
    def request = new MockHttpServletRequest()
    def response = new MockHttpServletResponse()
    def filterChain = new MockFilterChain()
    def filter = new CsrfHeaderFilter()

    def setup() {
        request.setContextPath('/app')
    }

    def "doFilterInternal - given no csrf token, should not create csrf cookie"() {
        when:
        filter.doFilterInternal(request, response, filterChain)

        then:
        response.getCookie(CsrfHeaderFilter.COOKIE_NAME) == null
    }

    def "doFilterInternal - given csrf token but no existing cookie, should create csrf cookie"() {
        given:
        request.setAttribute(CsrfToken.class.getName(),
                             new DefaultCsrfToken(CsrfHeaderFilter.HEADER_NAME, 'paramToken', 'token'))

        when:
        filter.doFilterInternal(request, response, filterChain)

        then:
        def cookie = response.getCookie(CsrfHeaderFilter.COOKIE_NAME)
        cookie.value == 'token'
        cookie.path == '/app'
        cookie.secure
        cookie.maxAge == 60 * 60 * 8
        !cookie.isHttpOnly()
    }

    def "doFilterInternal - given csrf token and existing cookie but with old token value, should create csrf cookie"() {
        given:
        request.setAttribute(CsrfToken.class.getName(),
                             new DefaultCsrfToken(CsrfHeaderFilter.HEADER_NAME, 'paramToken', 'token'))

        request.setCookies(new Cookie(CsrfHeaderFilter.COOKIE_NAME, 'old-token'))

        when:
        filter.doFilterInternal(request, response, filterChain)

        then:
        def cookie = response.getCookie(CsrfHeaderFilter.COOKIE_NAME)
        cookie.value == 'token'
        cookie.path == '/app'
        cookie.secure
        cookie.maxAge == 60 * 60 * 8
        !cookie.isHttpOnly()
    }

    def "doFilterInternal - given csrf token and existing cookie with matching token value, should not create csrf cookie"() {
        given:
        request.setAttribute(CsrfToken.class.getName(),
                             new DefaultCsrfToken(CsrfHeaderFilter.HEADER_NAME, 'paramToken', 'token'))

        request.setCookies(new Cookie(CsrfHeaderFilter.COOKIE_NAME, 'token'))

        when:
        filter.doFilterInternal(request, response, filterChain)

        then:
        response.getCookie(CsrfHeaderFilter.COOKIE_NAME) == null
    }
}
