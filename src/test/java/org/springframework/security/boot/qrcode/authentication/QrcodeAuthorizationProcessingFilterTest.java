/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.qrcode.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.exception.AuthenticationTokenNotFoundException;
import org.springframework.security.boot.qrcode.exception.AuthenticationQrcodeNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link QrcodeAuthorizationProcessingFilter }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("QrcodeAuthorizationProcessingFilter Tests")
class QrcodeAuthorizationProcessingFilterTest {

    private QrcodeAuthorizationProcessingFilter filter;
    private AuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        filter = new QrcodeAuthorizationProcessingFilter();
        authenticationManager = mock(AuthenticationManager.class);
        filter.setAuthenticationManager(authenticationManager);
    }

    @Test
    @DisplayName("Instance can be created via default constructor with default constants")
    void testInstantiation() {
        assertThat(filter).isNotNull();
        assertThat(filter.getAuthorizationHeaderName()).isEqualTo(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_HEADER);
        assertThat(filter.getAuthorizationParamName()).isEqualTo(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_PARAM);
        assertThat(filter.getAuthorizationCookieName()).isEqualTo(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_PARAM);
        assertThat(filter.getQrcodeParameter()).isEqualTo(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM);
        assertThat(filter.getSessionStrategy()).isNotNull();
    }

    @Test
    @DisplayName("Property setters and getters round-trip")
    void testSettersGetters() {
        filter.setAuthorizationHeaderName("X-Auth");
        filter.setAuthorizationParamName("tokenParam");
        filter.setAuthorizationCookieName("tokenCookie");
        filter.setQrcodeParameter("uuidParam");

        assertThat(filter.getAuthorizationHeaderName()).isEqualTo("X-Auth");
        assertThat(filter.getAuthorizationParamName()).isEqualTo("tokenParam");
        assertThat(filter.getAuthorizationCookieName()).isEqualTo("tokenCookie");
        assertThat(filter.getQrcodeParameter()).isEqualTo("uuidParam");

        SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
        filter.setSessionAuthenticationStrategy(strategy);
        assertThat(filter.getSessionStrategy()).isSameAs(strategy);
    }

    @Test
    @DisplayName("doFilter() delegates to chain when request path does not match")
    void testDoFilterNotRequiresAuth() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/some/other/path");
        request.setServletPath("/some/other/path");
        HttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(authenticationManager);
    }

    @Test
    @DisplayName("doAttemptAuthentication() throws AuthenticationQrcodeNotFoundException when uuid is blank")
    void testAttemptAuthMissingUuid() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> filter.doAttemptAuthentication(request, response))
                .isInstanceOf(AuthenticationQrcodeNotFoundException.class);
    }

    @Test
    @DisplayName("doAttemptAuthentication() throws AuthenticationTokenNotFoundException when token is blank")
    void testAttemptAuthMissingToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> filter.doAttemptAuthentication(request, response))
                .isInstanceOf(AuthenticationTokenNotFoundException.class);
    }

    @Test
    @DisplayName("doAttemptAuthentication() reads token from header first")
    void testAttemptAuthTokenFromHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        request.addHeader(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_HEADER, "header-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication authResult = mock(Authentication.class);
        when(authenticationManager.authenticate(any(QrcodeAuthorizationToken.class))).thenReturn(authResult);

        Authentication result = filter.doAttemptAuthentication(request, response);

        assertThat(result).isSameAs(authResult);
        verify(authenticationManager).authenticate(org.mockito.ArgumentMatchers.argThat(t ->
                QrcodeAuthorizationToken.class.isInstance(t)
                        && "header-token".equals(t.getPrincipal())
                        && "uuid-1".equals(t.getCredentials())));
    }

    @Test
    @DisplayName("doAttemptAuthentication() reads token from parameter when header missing")
    void testAttemptAuthTokenFromParameter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        request.addParameter(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_PARAM, "param-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication authResult = mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(authResult);

        Authentication result = filter.doAttemptAuthentication(request, response);

        assertThat(result).isSameAs(authResult);
    }

    @Test
    @DisplayName("doAttemptAuthentication() throws when token cannot be resolved (empty cookies)")
    void testAttemptAuthEmptyCookies() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        request.setCookies(new Cookie[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> filter.doAttemptAuthentication(request, response))
                .isInstanceOf(AuthenticationTokenNotFoundException.class);
    }

    @Test
    @DisplayName("doAttemptAuthentication() throws when cookies contain no matching token cookie")
    void testAttemptAuthCookieNoMatch() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        request.setCookies(new Cookie("other", "value"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> filter.doAttemptAuthentication(request, response))
                .isInstanceOf(AuthenticationTokenNotFoundException.class);
    }

    @Test
    @DisplayName("doFilter() invokes success handler on successful authentication")
    void testDoFilterSuccess() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/qrcode");
        request.setServletPath("/login/qrcode");
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        request.addHeader(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_HEADER, "jwt-token");
        HttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        Authentication authResult = mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(authResult);

        AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
        AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);

        filter.doFilter(request, response, chain);

        verify(successHandler).onAuthenticationSuccess(request, response, authResult);
        verifyNoInteractions(failureHandler, chain);
    }

    @Test
    @DisplayName("doFilter() invokes failure handler when AuthenticationException is thrown")
    void testDoFilterAuthenticationException() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/qrcode");
        request.setServletPath("/login/qrcode");
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        request.addHeader(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_HEADER, "jwt-token");
        HttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        AuthenticationException failure = new AuthenticationQrcodeNotFoundException("boom");
        when(authenticationManager.authenticate(any())).thenThrow(failure);

        AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
        filter.setAuthenticationFailureHandler(failureHandler);

        filter.doFilter(request, response, chain);

        verify(failureHandler).onAuthenticationFailure(request, response, failure);
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("doFilter() returns early without invoking handlers when authResult is null")
    void testDoFilterNullAuthResult() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/qrcode");
        request.setServletPath("/login/qrcode");
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        request.addHeader(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_HEADER, "jwt-token");
        HttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        when(authenticationManager.authenticate(any())).thenReturn(null);

        AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
        AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);

        filter.doFilter(request, response, chain);

        verifyNoInteractions(successHandler, failureHandler, chain);
    }

    @Test
    @DisplayName("doFilter() handles InternalAuthenticationServiceException via failure handler")
    void testDoFilterInternalAuthenticationServiceException() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/qrcode");
        request.setServletPath("/login/qrcode");
        request.addParameter(QrcodeAuthorizationProcessingFilter.QRCODE_UUID_PARAM, "uuid-1");
        request.addHeader(QrcodeAuthorizationProcessingFilter.AUTHORIZATION_HEADER, "jwt-token");
        HttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        org.springframework.security.authentication.InternalAuthenticationServiceException failure =
                new org.springframework.security.authentication.InternalAuthenticationServiceException("svc");
        when(authenticationManager.authenticate(any())).thenThrow(failure);

        AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
        filter.setAuthenticationFailureHandler(failureHandler);

        filter.doFilter(request, response, chain);

        verify(failureHandler).onAuthenticationFailure(request, response, failure);
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("setSessionAuthenticationStrategy override delegates to super and stores field")
    void testSetSessionAuthenticationStrategyOverride() {
        SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
        filter.setSessionAuthenticationStrategy(strategy);
        assertThat(filter.getSessionStrategy()).isSameAs(strategy);
    }
}
