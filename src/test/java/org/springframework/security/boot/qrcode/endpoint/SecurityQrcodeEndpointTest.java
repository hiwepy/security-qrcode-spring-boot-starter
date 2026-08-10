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
package org.springframework.security.boot.qrcode.endpoint;

import com.google.zxing.spring.boot.ZxingQrCodeTemplate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link SecurityQrcodeEndpoint }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityQrcodeEndpoint Tests")
class SecurityQrcodeEndpointTest {

    private StringRedisTemplate stringRedisTemplate;
    private ZxingQrCodeTemplate qrcodeTemplate;
    private ValueOperations<String, String> valueOps;
    private SecurityQrcodeEndpoint endpoint;

    @BeforeEach
    void setUp() {
        stringRedisTemplate = mock(StringRedisTemplate.class);
        qrcodeTemplate = mock(ZxingQrCodeTemplate.class);
        valueOps = mockValueOperations(null);
        when(stringRedisTemplate.opsForValue()).thenReturn(valueOps);
        endpoint = new SecurityQrcodeEndpoint(stringRedisTemplate, qrcodeTemplate);
    }

    @Test
    @DisplayName("Endpoint class can be instantiated with dependencies")
    void testInstantiation() {
        assertThat(endpoint).isNotNull();
        assertThat(endpoint.getStringRedisTemplate()).isSameAs(stringRedisTemplate);
        assertThat(endpoint.getQrcodeTemplate()).isSameAs(qrcodeTemplate);
    }

    @Test
    @DisplayName("qrcode() returns 200 with uuid and qrcode when generation succeeds")
    void testQrcodeSuccess() throws Exception {
        when(qrcodeTemplate.qrcodeBase64(anyString())).thenReturn("data:image/png;base64,xxx");

        ResponseEntity<Map<String, Object>> response = endpoint.qrcode();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("code")).isEqualTo(0);
        assertThat(response.getBody().get("uuid")).isNotNull();
        assertThat(response.getBody().get("qrcode")).isEqualTo("data:image/png;base64,xxx");
    }

    @Test
    @DisplayName("qrcode() returns 500 when an exception is thrown during generation")
    void testQrcodeFailure() throws Exception {
        when(qrcodeTemplate.qrcodeBase64(anyString())).thenThrow(new RuntimeException("boom"));

        ResponseEntity<Map<String, Object>> response = endpoint.qrcode();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("code")).isEqualTo(500);
    }

    @Test
    @DisplayName("bind() returns expired status and new uuid when key is missing")
    void testBindExpired() throws Exception {
        when(stringRedisTemplate.hasKey(anyString())).thenReturn(false);
        when(qrcodeTemplate.qrcodeBase64(anyString())).thenReturn("data:image/png;base64,new");

        ResponseEntity<Map<String, Object>> response = endpoint.bind("some-uuid");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("code")).isEqualTo(0);
        assertThat(response.getBody().get("status")).isEqualTo("expired");
        assertThat(response.getBody().get("uuid")).isNotNull();
        assertThat(response.getBody().get("qrcode")).isEqualTo("data:image/png;base64,new");
    }

    @Test
    @DisplayName("bind() returns unbind status when value is unbind")
    void testBindUnbind() {
        when(stringRedisTemplate.hasKey(anyString())).thenReturn(true);
        when(valueOps.get(anyString())).thenReturn("unbind");

        ResponseEntity<Map<String, Object>> response = endpoint.bind("some-uuid");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("status")).isEqualTo("unbind");
    }

    @Test
    @DisplayName("bind() returns bound status when value represents bound user data")
    void testBindBound() {
        when(stringRedisTemplate.hasKey(anyString())).thenReturn(true);
        when(valueOps.get(anyString())).thenReturn("{\"username\":\"admin\"}");

        ResponseEntity<Map<String, Object>> response = endpoint.bind("some-uuid");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("status")).isEqualTo("bound");
        assertThat(response.getBody().get("data")).isNotNull();
    }

    @Test
    @DisplayName("bind() returns 500 when an exception is thrown")
    void testBindFailure() {
        when(stringRedisTemplate.hasKey(anyString())).thenThrow(new RuntimeException("boom"));

        ResponseEntity<Map<String, Object>> response = endpoint.bind("some-uuid");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("code")).isEqualTo(500);
    }

    @SuppressWarnings("unchecked")
    private ValueOperations<String, String> mockValueOperations(String value) {
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(valueOps.get(anyString())).thenReturn(value);
        return valueOps;
    }
}
