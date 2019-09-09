package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationSuccessHandler;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.qrcode.endpoint.SecurityQrcodeEndpoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.RequestCache;

import com.google.zxing.spring.boot.ZxingQrCodeTemplate;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityQrcodeProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityQrcodeProperties.class })
public class SecurityQrcodeAutoConfiguration {

	@Autowired
	private SecurityBizProperties bizProperties;

	
	
	
	@Bean
	public QrcodeMatchedAuthenticationEntryPoint qrcodeMatchedAuthenticationEntryPoint() {
		return new QrcodeMatchedAuthenticationEntryPoint();
	}

	@Bean
	public QrcodeMatchedAuthenticationFailureHandler qrcodeMatchedAuthenticationFailureHandler() {
		return new QrcodeMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public QrcodeAuthorizationSuccessHandler qrcodeAuthorizationSuccessHandler(JwtPayloadRepository payloadRepository,
			StringRedisTemplate stringRedisTemplate) {
		return new QrcodeAuthorizationSuccessHandler(payloadRepository, stringRedisTemplate);
	}

	@Bean
	public SecurityQrcodeEndpoint securityQrcodeEndpoint(StringRedisTemplate stringRedisTemplate,
			ZxingQrCodeTemplate qrcodeTemplate) {
		return new SecurityQrcodeEndpoint(stringRedisTemplate, qrcodeTemplate);
	}

}
