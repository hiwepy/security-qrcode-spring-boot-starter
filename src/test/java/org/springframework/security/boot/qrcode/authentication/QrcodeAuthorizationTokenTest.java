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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {{ @link QrcodeAuthorizationToken }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("QrcodeAuthorizationToken Tests")
class QrcodeAuthorizationTokenTest {

    @Test
    @DisplayName("Single-arg constructor stores principal and is unauthenticated")
    void testSingleArgConstructor() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("principal");
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getCredentials()).isNull();
        assertThat(token.isAuthenticated()).isFalse();
        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    @DisplayName("Two-arg constructor stores principal and credentials and is unauthenticated")
    void testTwoArgConstructor() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("principal", "credentials");
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getCredentials()).isEqualTo("credentials");
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("Three-arg constructor with authorities is authenticated")
    void testThreeArgConstructorAuthenticated() {
        Collection<? extends GrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("principal", "credentials", authorities);
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getPrincipal()).isEqualTo("principal");
        assertThat(token.getCredentials()).isEqualTo("credentials");
        assertThat(token.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("setAuthenticated(true) throws IllegalArgumentException")
    void testSetAuthenticatedTrueThrows() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("principal");
        assertThatThrownBy(() -> token.setAuthenticated(true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("setAuthenticated(false) keeps token unauthenticated")
    void testSetAuthenticatedFalse() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("principal");
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("eraseCredentials() clears credentials")
    void testEraseCredentials() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("principal", "credentials");
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    @DisplayName("getName() returns principal string when principal is not UserDetails")
    void testGetName() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("principal");
        assertThat(token.getName()).isEqualTo("principal");
    }
}
