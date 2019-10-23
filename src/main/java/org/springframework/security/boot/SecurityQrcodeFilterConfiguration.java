package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationProcessingFilter;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationProvider;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityQrcodeProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityQrcodeProperties.class, SecurityQrcodeAuthzProperties.class, 
	SecurityBizProperties.class, ServerProperties.class })
public class SecurityQrcodeFilterConfiguration {
 
	@Bean
	public QrcodeAuthorizationProvider qrcodeAuthorizationProvider(JwtPayloadRepository payloadRepository,
    		UserDetailsServiceAdapter userDetailsService) {
		return new QrcodeAuthorizationProvider(payloadRepository, userDetailsService);
	}
	
	@Configuration
	@EnableConfigurationProperties({ SecurityQrcodeProperties.class, SecurityQrcodeAuthzProperties.class, SecurityBizProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 2)
	static class QrcodeWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {

	    private final SecurityQrcodeAuthzProperties authcProperties;
	    
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	    
		public QrcodeWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
				SecurityQrcodeAuthzProperties authzProperties,

				ObjectProvider<QrcodeAuthorizationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<QrcodeAuthorizationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider
				
			) {
			
			super(bizProperties, authzProperties, authenticationProvider.stream().collect(Collectors.toList()),
					authenticationManagerProvider.getIfAvailable());
			
			this.authcProperties = authzProperties;
			
			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = authenticationSuccessHandlerProvider.getIfAvailable();
   			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.requestCache = super.requestCache();
   			this.rememberMeServices = super.rememberMeServices();
   			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();
   			
		}

		public QrcodeAuthorizationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
			QrcodeAuthorizationProcessingFilter authenticationFilter = new QrcodeAuthorizationProcessingFilter();
			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authcProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getAuthorizationCookieName()).to(authenticationFilter::setAuthorizationCookieName);
			map.from(authcProperties.getAuthorizationHeaderName()).to(authenticationFilter::setAuthorizationHeaderName);
			map.from(authcProperties.getAuthorizationParamName()).to(authenticationFilter::setAuthorizationParamName);
			
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			
	        return authenticationFilter;
	    }
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			
   		    // Session 管理器配置
   	    	http.requestCache()
   	        	.requestCache(requestCache)
   	        	// 异常处理
   	        	.and()
   	        	.exceptionHandling()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.httpBasic()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.antMatcher(authcProperties.getPathPattern())
   	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 

   	    	super.configure(http, authcProperties.getCors());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
	    	
		}
		
		@Override
	    public void configure(WebSecurity web) throws Exception {
	    	super.configure(web);
	    }
		
	}
	
}
