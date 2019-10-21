package org.springframework.security.boot;

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
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationProcessingFilter;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationProvider;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthorizationSuccessHandler;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

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

		private final SecurityBizProperties bizProperties;
	    private final SecurityQrcodeAuthzProperties qrcodeAuthzProperties;
	    
	    
	    private final AuthenticationManager authenticationManager;
	    private final RememberMeServices rememberMeServices;
	    
	    private final QrcodeAuthorizationProvider qrcodeAuthorizationProvider;
	    private final QrcodeAuthorizationSuccessHandler authorizationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authorizationFailureHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	
		public QrcodeWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
				SecurityQrcodeAuthzProperties qrcodeAuthzProperties,

				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
				ObjectProvider<PostRequestAuthenticationFailureHandler> authorizationFailureHandler,
				ObjectProvider<QrcodeAuthorizationProvider> qrcodeAuthorizationProvider,
				ObjectProvider<QrcodeAuthorizationSuccessHandler> authorizationSuccessHandler,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider
				
			) {
			
			super(bizProperties);
			
			this.bizProperties = bizProperties;
			this.qrcodeAuthzProperties = qrcodeAuthzProperties;
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			
			this.qrcodeAuthorizationProvider = qrcodeAuthorizationProvider.getIfAvailable();
			this.authorizationSuccessHandler = authorizationSuccessHandler.getIfAvailable();
   			this.authorizationFailureHandler = authorizationFailureHandler.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

		public QrcodeAuthorizationProcessingFilter authenticationProcessingFilter() throws Exception {
	    	
			QrcodeAuthorizationProcessingFilter authenticationFilter = new QrcodeAuthorizationProcessingFilter();
			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authorizationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authorizationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(qrcodeAuthzProperties.getAuthorizationCookieName()).to(authenticationFilter::setAuthorizationCookieName);
			map.from(qrcodeAuthzProperties.getAuthorizationHeaderName()).to(authenticationFilter::setAuthorizationHeaderName);
			map.from(qrcodeAuthzProperties.getAuthorizationParamName()).to(authenticationFilter::setAuthorizationParamName);
			
			map.from(qrcodeAuthzProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			
	        return authenticationFilter;
	    }
		
	    @Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(qrcodeAuthorizationProvider);
	        super.configure(auth);
	    }
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.antMatcher(qrcodeAuthzProperties.getPathPattern())
				.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
			super.configure(http);
		}
		
		@Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	super.configure(web);
   	    }
		
	}
	
}
