package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthenticationProvider;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.qrcode.authentication.QrcodeRecognitionProvider;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityQrcodeProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityQrcodeProperties.class })
public class SecurityQrcodeAutoConfiguration {

	@Bean
	public QrcodeMatchedAuthenticationEntryPoint idcMatchedAuthenticationEntryPoint() {
		return new QrcodeMatchedAuthenticationEntryPoint();
	}

	@Bean
	public QrcodeMatchedAuthenticationFailureHandler idcMatchedAuthenticationFailureHandler() {
		return new QrcodeMatchedAuthenticationFailureHandler();
	}

	@Bean
	public QrcodeAuthenticationProvider idcCodeAuthenticationProvider(QrcodeRecognitionProvider faceRecognitionProvider,
			UserDetailsServiceAdapter userDetailsService) {
		return new QrcodeAuthenticationProvider(faceRecognitionProvider, userDetailsService);
	}

}
