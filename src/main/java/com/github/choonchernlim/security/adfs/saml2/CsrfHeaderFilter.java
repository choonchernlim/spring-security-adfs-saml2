package com.github.choonchernlim.security.adfs.saml2;

import com.google.common.base.MoreObjects;
import com.google.common.base.Strings;
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

            // If there's no existing cookie or the token value doesn't match, create/update it.
            //
            // `domain`     =   Don't need to set this so that the current request's domain will be used.
            // `httpOnly`   =   Cannot set this value because we need JS to be able to read this cookie to get the token.
            // `path`       =   Match app's root context so that only the app can access this cooke.
            //                  If path is empty, set it as '/' to prevent using the resource path currently requested.
            //                  This prevents creating too many cookies with the same name but different paths
            //                  (due to bookmark-able links) because client side will have difficulties grabbing
            //                  the right CSRF token value from the right cookie.
            //                  Regarding path not set, see See https://en.wikipedia.org/wiki/HTTP_cookie#Domain_and_path
            //
            // `secure`     =   Cookie to only be transmitted over secure protocol as https
            //
            // `maxAge`     =   Expire the cookie after 8 hours. Cannot use HTTP session timeout value because this
            //                  cookie will only get created/updated if the token value is different instead of
            //                  every time user refreshes the session by interacting with server side.
            if (existingCookie == null || !token.equals(existingCookie.getValue())) {
                final Cookie cookie = new Cookie(COOKIE_NAME, token);
                final String path = MoreObjects.firstNonNull(
                        Strings.emptyToNull(request.getServletContext().getContextPath()), "/");

                cookie.setPath(path);
                cookie.setSecure(true);
                cookie.setMaxAge(60 * 60 * 8);
                response.addCookie(cookie);
            }
        }

        filterChain.doFilter(request, response);
    }
}
