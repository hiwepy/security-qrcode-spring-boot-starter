package org.springframework.security.boot;

import com.google.zxing.spring.boot.ZxingQrCodeTemplate;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationSuccessHandler;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.qrcode.endpoint.SecurityQrcodeEndpoint;

/**
 * Auto-configuration for QR code-based security authentication.
 * <p>Registers QR code authentication entry point, failure handler, success handler
 * and endpoint when QR code authentication is enabled.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityQrcodeProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityQrcodeProperties.class })
public class SecurityQrcodeAutoConfiguration {
	
	/**
	 * Creates the QR code authentication entry point.
	 * @return the entry point
	 */
	@Bean
	public QrcodeMatchedAuthenticationEntryPoint qrcodeMatchedAuthenticationEntryPoint() {
		return new QrcodeMatchedAuthenticationEntryPoint();
	}

	/**
	 * Creates the QR code authentication failure handler.
	 * @return the failure handler
	 */
	@Bean
	public QrcodeMatchedAuthenticationFailureHandler qrcodeMatchedAuthenticationFailureHandler() {
		return new QrcodeMatchedAuthenticationFailureHandler();
	}
	
	/**
	 * Creates the QR code authorization success handler.
	 * @param payloadRepository the JWT payload repository
	 * @param stringRedisTemplate the Redis template for storing QR code data
	 * @return the success handler
	 */
	@Bean
	@ConditionalOnMissingBean
	public QrcodeAuthorizationSuccessHandler qrcodeAuthorizationSuccessHandler(JwtPayloadRepository payloadRepository,
			StringRedisTemplate stringRedisTemplate) {
		return new QrcodeAuthorizationSuccessHandler(payloadRepository, stringRedisTemplate);
	}

	/**
	 * Creates the security QR code endpoint.
	 * @param stringRedisTemplate the Redis template for QR code storage
	 * @param qrcodeTemplate the QR code generation template
	 * @return the endpoint
	 */
	@Bean
	public SecurityQrcodeEndpoint securityQrcodeEndpoint(StringRedisTemplate stringRedisTemplate,
			ZxingQrCodeTemplate qrcodeTemplate) {
		return new SecurityQrcodeEndpoint(stringRedisTemplate, qrcodeTemplate);
	}

}
