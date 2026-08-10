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
package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationProcessingFilter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {{ @link SecurityQrcodeFilterConfiguration }} and its nested
 * {{ @link SecurityQrcodeFilterConfiguration.QrcodeWebSecurityCustomizerAdapter }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityQrcodeFilterConfiguration Tests")
class SecurityQrcodeFilterConfigurationTest {

    @Test
    @DisplayName("Configuration class can be instantiated")
    void testInstantiation() {
        SecurityQrcodeFilterConfiguration configuration = new SecurityQrcodeFilterConfiguration();
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("QrcodeWebSecurityCustomizerAdapter can be constructed with empty providers")
    void testAdapterConstruction() throws Exception {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecuritySessionMgtProperties sessionMgtProperties = new SecuritySessionMgtProperties();
        SecurityQrcodeAuthzProperties authzProperties = new SecurityQrcodeAuthzProperties();

        SecurityQrcodeFilterConfiguration.QrcodeWebSecurityCustomizerAdapter adapter =
                new SecurityQrcodeFilterConfiguration.QrcodeWebSecurityCustomizerAdapter(
                        bizProperties,
                        sessionMgtProperties,
                        authzProperties,
                        emptyProvider(AccessDeniedHandler.class),
                        emptyProvider(LocaleContextFilter.class),
                        providerOf(mock(AuthenticationProvider.class)),
                        emptyProvider(AuthenticationListener.class),
                        emptyProvider(MatchedAuthenticationEntryPoint.class),
                        emptyProvider(MatchedAuthenticationSuccessHandler.class),
                        emptyProvider(MatchedAuthenticationFailureHandler.class),
                        emptyProvider(RememberMeServices.class),
                        emptyProvider(SessionAuthenticationStrategy.class)
                );

        assertThat(adapter).isNotNull();
        assertThat(adapter.getSessionMgtProperties()).isSameAs(sessionMgtProperties);

        // authenticationProcessingFilter builds a configured filter from properties
        QrcodeAuthorizationProcessingFilter filter = adapter.authenticationProcessingFilter();
        assertThat(filter).isNotNull();
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> emptyProvider(Class<T> type) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        when(provider.stream()).thenReturn(Collections.<T>emptyList().stream());
        return provider;
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> providerOf(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        when(provider.stream()).thenReturn(Collections.singletonList(value).stream());
        return provider;
    }
}
