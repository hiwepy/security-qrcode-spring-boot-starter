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

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.qrcode.exception.AuthenticationQrcodeNotFoundException;
import org.springframework.security.core.AuthenticationException;

import java.io.ByteArrayOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link QrcodeMatchedAuthenticationFailureHandler }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("QrcodeMatchedAuthenticationFailureHandler Tests")
class QrcodeMatchedAuthenticationFailureHandlerTest {

    private QrcodeMatchedAuthenticationFailureHandler handler;

    @BeforeEach
    void setUp() {
        handler = new QrcodeMatchedAuthenticationFailureHandler();
    }

    @Test
    @DisplayName("supports() returns true only for AuthenticationQrcodeNotFoundException")
    void testSupports() {
        assertThat(handler.supports(new AuthenticationQrcodeNotFoundException("x"))).isTrue();
        assertThat(handler.supports(new AuthenticationException("other") {
        })).isFalse();
    }

    @Test
    @DisplayName("onAuthenticationFailure() writes JSON response with code-required status for qrcode exception")
    void testOnAuthenticationFailureQrcodeException() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream out = captureOutput(response);

        handler.onAuthenticationFailure(request, response, new AuthenticationQrcodeNotFoundException("missing"));

        verify(response).setStatus(200);
        verify(response).setContentType("application/json");
        assertThat(out.toByteArray()).isNotEmpty();
    }

    @Test
    @DisplayName("onAuthenticationFailure() writes generic authz-fail response for other exceptions")
    void testOnAuthenticationFailureOtherException() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream out = captureOutput(response);

        handler.onAuthenticationFailure(request, response, new AuthenticationException("other") {
        });

        verify(response).setStatus(200);
        assertThat(out.toByteArray()).isNotEmpty();
    }

    private ByteArrayOutputStream captureOutput(HttpServletResponse response) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
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
        return out;
    }
}
