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
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthenticationProvider;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.qrcode.authentication.QrcodeMatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.qrcode.authentication.QrcodeRecognitionProvider;
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
	@Autowired
	private SecurityQrcodeProperties qrcodeProperties;

	@Bean("qrcodeAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler qrcodeAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers, 
			RedirectStrategy redirectStrategy, 
			RequestCache requestCache) {
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		successHandler.setDefaultTargetUrl(qrcodeProperties.getAuthc().getSuccessUrl());
		successHandler.setRedirectStrategy(redirectStrategy);
		successHandler.setRequestCache(requestCache);
		successHandler.setStateless(bizProperties.isStateless());
		//successHandler.setTargetUrlParameter(qrcodeProperties.getAuthc().getTargetUrlParameter());
		successHandler.setUseReferer(qrcodeProperties.getAuthc().isUseReferer());
		return successHandler;
	}
	
	@Bean("qrcodeAuthenticationFailureHandler")
	public PostRequestAuthenticationFailureHandler qrcodeAuthenticationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationFailureHandler> failureHandlers, 
			RedirectStrategy redirectStrategy) {
		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);
		failureHandler.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(qrcodeProperties.getAuthc().getFailureUrl());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setStateless(bizProperties.isStateless());
		failureHandler.setUseForward(qrcodeProperties.getAuthc().isUseForward());
		return failureHandler;
	}
	
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
	public QrcodeMatchedAuthenticationSuccessHandler qrcodeMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository,
			StringRedisTemplate stringRedisTemplate) {
		return new QrcodeMatchedAuthenticationSuccessHandler(payloadRepository, stringRedisTemplate);
	}

	@Bean
	public QrcodeAuthenticationProvider idcCodeAuthenticationProvider(QrcodeRecognitionProvider faceRecognitionProvider,
			UserDetailsServiceAdapter userDetailsService) {
		return new QrcodeAuthenticationProvider(faceRecognitionProvider, userDetailsService);
	}

	@Bean
	public SecurityQrcodeEndpoint securityQrcodeEndpoint(StringRedisTemplate stringRedisTemplate,
			ZxingQrCodeTemplate qrcodeTemplate) {
		return new SecurityQrcodeEndpoint(stringRedisTemplate, qrcodeTemplate);
	}

}
