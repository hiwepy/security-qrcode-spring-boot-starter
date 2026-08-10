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
package org.springframework.security.boot.qrcode.userdetails;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link QrcodePrincipal }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("QrcodePrincipal Tests")
class QrcodePrincipalTest {

    @Test
    @DisplayName("Roles constructor populates authorities and default account flags")
    void testRolesConstructor() {
        QrcodePrincipal principal = new QrcodePrincipal("admin", "pwd", "ADMIN", "USER");

        assertThat(principal.getUsername()).isEqualTo("admin");
        assertThat(principal.getPassword()).isEqualTo("pwd");
        assertThat(principal.isAccountNonExpired()).isTrue();
        assertThat(principal.isAccountNonLocked()).isTrue();
        assertThat(principal.isCredentialsNonExpired()).isTrue();
        assertThat(principal.isEnabled()).isTrue();
        assertThat(principal.getUuid()).isNull();
    }

    @Test
    @DisplayName("Authorities-collection constructor populates authorities")
    void testAuthoritiesConstructor() {
        Collection<? extends GrantedAuthority> authorities =
                Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
        QrcodePrincipal principal = new QrcodePrincipal("user", "pwd", authorities);

        assertThat(principal.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("Full constructor populates account flags")
    void testFullConstructor() {
        Collection<? extends GrantedAuthority> authorities = Collections.emptyList();
        QrcodePrincipal principal = new QrcodePrincipal("user", "pwd",
                false, false, false, false, authorities);

        assertThat(principal.isEnabled()).isFalse();
        assertThat(principal.isAccountNonExpired()).isFalse();
        assertThat(principal.isCredentialsNonExpired()).isFalse();
        assertThat(principal.isAccountNonLocked()).isFalse();
    }

    @Test
    @DisplayName("uuid getter/setter round-trip")
    void testUuidAccessor() {
        QrcodePrincipal principal = new QrcodePrincipal("user", "pwd");
        principal.setUuid("uuid-1");
        assertThat(principal.getUuid()).isEqualTo("uuid-1");
    }
}
