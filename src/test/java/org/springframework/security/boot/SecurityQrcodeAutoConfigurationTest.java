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

import com.google.zxing.spring.boot.ZxingQrCodeTemplate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {{ @link SecurityQrcodeAutoConfiguration }}.
 *
 * <p>Verifies the auto-configuration activates under the expected conditions
 * and exposes its declared beans.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecurityQrcodeAutoConfiguration Tests")
class SecurityQrcodeAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withBean(JwtPayloadRepository.class, () -> mock(JwtPayloadRepository.class))
            .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
            .withBean(ZxingQrCodeTemplate.class, () -> mock(ZxingQrCodeTemplate.class));

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        SecurityQrcodeAutoConfiguration configuration = new SecurityQrcodeAutoConfiguration();
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("Auto-configuration loads when 'spring.security.qrcode.enabled=true'")
    void testLoadsWhenEnabledPropertySet() {
        runner.withUserConfiguration(SecurityQrcodeAutoConfiguration.class)
                .withPropertyValues("spring.security.qrcode.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(SecurityQrcodeAutoConfiguration.class));
    }

    @Test
    @DisplayName("Auto-configuration is absent when property is not set")
    void testNotLoadedWhenPropertyAbsent() {
        runner.withUserConfiguration(SecurityQrcodeAutoConfiguration.class)
                .run(context -> assertThat(context).doesNotHaveBean(SecurityQrcodeAutoConfiguration.class));
    }
}
