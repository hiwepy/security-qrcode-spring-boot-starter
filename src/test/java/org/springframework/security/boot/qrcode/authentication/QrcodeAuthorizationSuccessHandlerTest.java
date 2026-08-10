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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.boot.qrcode.userdetails.QrcodePrincipal;
import org.springframework.security.core.Authentication;

import java.io.ByteArrayOutputStream;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link QrcodeAuthorizationSuccessHandler }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("QrcodeAuthorizationSuccessHandler Tests")
class QrcodeAuthorizationSuccessHandlerTest {

    private JwtPayloadRepository payloadRepository;
    private StringRedisTemplate stringRedisTemplate;
    private QrcodeAuthorizationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        payloadRepository = mock(JwtPayloadRepository.class);
        stringRedisTemplate = mock(StringRedisTemplate.class);
        handler = new QrcodeAuthorizationSuccessHandler(payloadRepository, stringRedisTemplate);
    }

    @Test
    @DisplayName("Instance can be created and exposes collaborators")
    void testInstantiation() {
        assertThat(handler).isNotNull();
        assertThat(handler.getPayloadRepository()).isSameAs(payloadRepository);
        assertThat(handler.getStringRedisTemplate()).isSameAs(stringRedisTemplate);
        assertThat(handler.isCheckExpiry()).isFalse();
    }

    @Test
    @DisplayName("supports() returns true only for QrcodeAuthorizationToken")
    void testSupports() {
        assertThat(handler.supports(new QrcodeAuthorizationToken("p"))).isTrue();
        assertThat(handler.supports(mock(Authentication.class))).isFalse();
    }

    @Test
    @DisplayName("setCheckExpiry updates the flag")
    void testSetCheckExpiry() {
        handler.setCheckExpiry(true);
        assertThat(handler.isCheckExpiry()).isTrue();
    }

    @Test
    @DisplayName("onAuthenticationSuccess() writes JSON response and caches login info")
    void testOnAuthenticationSuccess() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) {
                out.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(jakarta.servlet.WriteListener writeListener) {
                // no-op
            }
        });

        QrcodePrincipal principal = new QrcodePrincipal("admin", "pwd");
        principal.setUuid("uuid-1");
        QrcodeAuthorizationToken authentication = new QrcodeAuthorizationToken(principal, "creds");

        UserProfilePayload profilePayload = new UserProfilePayload();
        when(payloadRepository.getProfilePayload(authentication, false)).thenReturn(profilePayload);

        @SuppressWarnings("unchecked")
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(stringRedisTemplate.opsForValue()).thenReturn(valueOps);

        handler.onAuthenticationSuccess(request, response, authentication);

        verify(response).setStatus(200);
        verify(response).setContentType("application/json");
        verify(valueOps).set(anyString(), any(), org.mockito.ArgumentMatchers.isA(Duration.class));
        // some JSON should have been written to the output stream
        assertThat(out.toByteArray()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationSuccess() skips caching when principal is not a QrcodePrincipal")
    void testOnAuthenticationSuccessNonQrcodePrincipal() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) {
                out.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(jakarta.servlet.WriteListener writeListener) {
                // no-op
            }
        });

        // principal that is a UserDetails but not a QrcodePrincipal
        org.springframework.security.core.userdetails.User plainUser =
                new org.springframework.security.core.userdetails.User("admin", "pwd",
                        java.util.Collections.emptySet());
        QrcodeAuthorizationToken authentication = new QrcodeAuthorizationToken(plainUser, "creds");

        UserProfilePayload profilePayload = new UserProfilePayload();
        when(payloadRepository.getProfilePayload(authentication, false)).thenReturn(profilePayload);

        handler.onAuthenticationSuccess(request, response, authentication);

        // opsForValue().set should never be invoked because principal is not QrcodePrincipal
        verify(stringRedisTemplate, org.mockito.Mockito.never()).opsForValue();
        assertThat(out.toByteArray()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationSuccess() clears attributes from session when session exists")
    void testClearAuthenticationAttributesWithSession() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) {
                out.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(jakarta.servlet.WriteListener writeListener) {
                // no-op
            }
        });
        HttpSession session = mock(HttpSession.class);
        when(request.getSession(false)).thenReturn(session);

        org.springframework.security.core.userdetails.User plainUser =
                new org.springframework.security.core.userdetails.User("admin", "pwd",
                        java.util.Collections.emptySet());
        QrcodeAuthorizationToken authentication = new QrcodeAuthorizationToken(plainUser, "creds");
        when(payloadRepository.getProfilePayload(authentication, false)).thenReturn(new UserProfilePayload());

        handler.onAuthenticationSuccess(request, response, authentication);

        verify(session).removeAttribute(org.springframework.security.web.WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}
