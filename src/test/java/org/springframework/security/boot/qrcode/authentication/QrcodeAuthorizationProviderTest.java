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

import io.github.easy4j.jwt.JwtPayload;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.exception.AuthenticationTokenNotFoundException;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.qrcode.exception.AuthenticationQrcodeNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link QrcodeAuthorizationProvider }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("QrcodeAuthorizationProvider Tests")
class QrcodeAuthorizationProviderTest {

    private JwtPayloadRepository payloadRepository;
    private UserDetailsServiceAdapter userDetailsService;
    private QrcodeAuthorizationProvider provider;

    @BeforeEach
    void setUp() {
        payloadRepository = mock(JwtPayloadRepository.class);
        userDetailsService = mock(UserDetailsServiceAdapter.class);
        provider = new QrcodeAuthorizationProvider(payloadRepository, userDetailsService);
    }

    @Test
    @DisplayName("Instance can be created via constructor and exposes collaborators")
    void testInstantiation() {
        assertThat(provider).isNotNull();
        assertThat(provider.getPayloadRepository()).isSameAs(payloadRepository);
        assertThat(provider.getUserDetailsService()).isSameAs(userDetailsService);
        assertThat(provider.isCheckExpiry()).isFalse();
        assertThat(provider.getUserDetailsChecker()).isNotNull();
    }

    @Test
    @DisplayName("supports() returns true only for QrcodeAuthorizationToken")
    void testSupports() {
        assertThat(provider.supports(QrcodeAuthorizationToken.class)).isTrue();
        assertThat(provider.supports(Object.class)).isFalse();
    }

    @Test
    @DisplayName("setCheckExpiry / setUserDetailsChecker update state")
    void testSetters() {
        provider.setCheckExpiry(true);
        assertThat(provider.isCheckExpiry()).isTrue();

        UserDetailsChecker checker = mock(UserDetailsChecker.class);
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isSameAs(checker);
    }

    @Test
    @DisplayName("authenticate() throws when authentication is null")
    void testAuthenticateNull() {
        assertThatThrownBy(() -> provider.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("authenticate() throws AuthenticationTokenNotFoundException when token is blank")
    void testAuthenticateBlankToken() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("", "uuid");
        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(AuthenticationTokenNotFoundException.class);
    }

    @Test
    @DisplayName("authenticate() throws AuthenticationQrcodeNotFoundException when uuid is blank")
    void testAuthenticateBlankUuid() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("jwt", "");
        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(AuthenticationQrcodeNotFoundException.class);
    }

    @Test
    @DisplayName("authenticate() builds an authenticated token with authorities on success")
    void testAuthenticateSuccess() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("jwt", "uuid-1");
        token.setDetails("details");

        JwtPayload payload = newPayload("ADMIN", new HashSet<>(java.util.Arrays.asList("user:read", "user:write")));
        when(payloadRepository.getPayload(token, false)).thenReturn(payload);

        Authentication result = provider.authenticate(token);

        assertThat(result).isInstanceOf(QrcodeAuthorizationToken.class);
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isNotNull();
        assertThat(result.getCredentials()).isSameAs(payload);
        assertThat(result.getDetails()).isEqualTo("details");

        // authorities should contain ROLE_ADMIN plus the two perms
        assertThat(result.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_ADMIN", "user:read", "user:write");
        // payload account flags should have been set to true
        assertThat(payload.isEnabled()).isTrue();
        assertThat(payload.isAccountNonExpired()).isTrue();
        assertThat(payload.isAccountNonLocked()).isTrue();
        assertThat(payload.isCredentialsNonExpired()).isTrue();

        verify(payloadRepository, atLeastOnce()).getPayload(token, false);
    }

    @Test
    @DisplayName("authenticate() honors checkExpiry flag when retrieving payload")
    void testAuthenticateCheckExpiryFlag() {
        provider.setCheckExpiry(true);
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("jwt", "uuid-1");
        JwtPayload payload = newPayload("USER", Collections.emptySet());
        when(payloadRepository.getPayload(token, true)).thenReturn(payload);

        Authentication result = provider.authenticate(token);

        assertThat(result.isAuthenticated()).isTrue();
        verify(payloadRepository).getPayload(token, true);
    }

    @Test
    @DisplayName("authenticate() works with empty perms set")
    void testAuthenticateEmptyPerms() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("jwt", "uuid-1");
        JwtPayload payload = newPayload("GUEST", Collections.emptySet());
        when(payloadRepository.getPayload(token, false)).thenReturn(payload);

        Authentication result = provider.authenticate(token);

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_GUEST");
    }

    @Test
    @DisplayName("authenticate() throws NPE when perms is null (defensive behavior)")
    void testAuthenticateNullPerms() {
        QrcodeAuthorizationToken token = new QrcodeAuthorizationToken("jwt", "uuid-1");
        JwtPayload payload = newPayload("GUEST", null);
        when(payloadRepository.getPayload(token, false)).thenReturn(payload);

        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(NullPointerException.class);
    }

    /** Builds a spied JwtPayload with controlled rkey/perms (no public setters for these). */
    private JwtPayload newPayload(String rkey, Set<String> perms) {
        JwtPayload payload = spy(new JwtPayload());
        when(payload.getRkey()).thenReturn(rkey);
        when(payload.getPerms()).thenReturn(perms);
        when(payload.getSubject()).thenReturn("subject-1");
        when(payload.getTokenId()).thenReturn("tid-1");
        return payload;
    }
}
