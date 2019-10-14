package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
	@Order(108)
	static class QrcodeWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

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
			
			this.bizProperties = bizProperties;
			this.qrcodeAuthzProperties = qrcodeAuthzProperties;
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			
			this.qrcodeAuthorizationProvider = qrcodeAuthorizationProvider.getIfAvailable();
			this.authorizationSuccessHandler = authorizationSuccessHandler.getIfAvailable();
   			this.authorizationFailureHandler = authorizationFailureHandler.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

		@Bean
		public QrcodeAuthorizationProcessingFilter qrcodeAuthorizationProcessingFilter() throws Exception {
	    	
			QrcodeAuthorizationProcessingFilter authzFilter = new QrcodeAuthorizationProcessingFilter();

			authzFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
			authzFilter.setAuthenticationFailureHandler(authorizationFailureHandler);
			authzFilter.setAuthenticationManager(authenticationManager);
			authzFilter.setAuthenticationSuccessHandler(authorizationSuccessHandler);
			if (StringUtils.hasText(qrcodeAuthzProperties.getPathPattern())) {
				authzFilter.setFilterProcessesUrl(qrcodeAuthzProperties.getPathPattern());
			}
			authzFilter.setAuthorizationCookieName(qrcodeAuthzProperties.getAuthorizationCookieName());
			authzFilter.setAuthorizationHeaderName(qrcodeAuthzProperties.getAuthorizationHeaderName());
			authzFilter.setAuthorizationParamName(qrcodeAuthzProperties.getAuthorizationParamName());
			authzFilter.setRememberMeServices(rememberMeServices);
			authzFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
			
	        return authzFilter;
	    }
		
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) {
	        auth.authenticationProvider(qrcodeAuthorizationProvider);
	    }
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.addFilterBefore(qrcodeAuthorizationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
		}
		
		@Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	web.ignoring().antMatchers(qrcodeAuthzProperties.getPathPattern());
   	    }
		
	}
	
}
