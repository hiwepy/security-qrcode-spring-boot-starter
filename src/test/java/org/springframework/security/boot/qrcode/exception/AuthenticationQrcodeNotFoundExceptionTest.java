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
package org.springframework.security.boot.qrcode.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link AuthenticationQrcodeNotFoundException }}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("AuthenticationQrcodeNotFoundException Tests")
class AuthenticationQrcodeNotFoundExceptionTest {

    @Test
    @DisplayName("Message-only constructor stores message")
    void testMessageConstructor() {
        AuthenticationQrcodeNotFoundException ex = new AuthenticationQrcodeNotFoundException("missing uuid");
        assertThat(ex.getMessage()).isEqualTo("missing uuid");
        assertThat(ex.getCause()).isNull();
    }

    @Test
    @DisplayName("Message-and-cause constructor stores message and cause")
    void testMessageAndCauseConstructor() {
        Throwable cause = new RuntimeException("root");
        AuthenticationQrcodeNotFoundException ex =
                new AuthenticationQrcodeNotFoundException("missing uuid", cause);
        assertThat(ex.getMessage()).isEqualTo("missing uuid");
        assertThat(ex.getCause()).isSameAs(cause);
    }
}
