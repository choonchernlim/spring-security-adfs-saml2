package com.github.choonchernlim.security.adfs.saml2;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter to pass CSRF token to single-page app through cookie.
 * <p>
 * This approach is approved by Rob Winch, the project lead of Spring Security.
 */
final class CsrfHeaderFilter extends OncePerRequestFilter {
    /**
     * Header name to match AngularJS's spec to ensure this filter is more compatible with major
     * client-side MV* frameworks.
     */
    static final String HEADER_NAME = "X-XSRF-TOKEN";

    /**
     * Cookie name to match AngularJS's spec to ensure this filter is more compatible with major
     * client-side MV* frameworks.
     */
    static final String COOKIE_NAME = "XSRF-TOKEN";

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain)
            throws ServletException, IOException {

        final CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        if (csrf != null) {
            final String token = csrf.getToken();
            final Cookie existingCookie = WebUtils.getCookie(request, COOKIE_NAME);

            if (existingCookie == null || !token.equals(existingCookie.getValue())) {
                // `path`   = while it doesn't provide any added security, set to context path to be consistent with `JSESSIONID` cookie
                // `secure` = cookie to only be transmitted over secure protocol as https
                // `maxAge` = expire the cookie after 8 hours
                final Cookie cookie = new Cookie(COOKIE_NAME, token);
                cookie.setPath(request.getContextPath());
                cookie.setSecure(true);
                cookie.setMaxAge(60 * 60 * 8);
                response.addCookie(cookie);
            }
        }

        filterChain.doFilter(request, response);
    }
}
