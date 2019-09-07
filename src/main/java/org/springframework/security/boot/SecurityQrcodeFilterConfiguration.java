package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthenticationProcessingFilter;
import org.springframework.security.boot.qrcode.authentication.QrcodeAuthenticationProvider;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration"
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityQrcodeProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityQrcodeProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityQrcodeFilterConfiguration {
 
	@Configuration
	@EnableConfigurationProperties({ SecurityQrcodeProperties.class, SecurityBizProperties.class })
	static class QrcodeWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		private final SecurityBizProperties bizProperties;
	    private final SecurityQrcodeProperties qrcodeProperties;
	    
	    private final AuthenticationManager authenticationManager;
	    private final RememberMeServices rememberMeServices;
	    
	    private final QrcodeAuthenticationProvider qrcodeAuthenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	
		public QrcodeWebSecurityConfigurerAdapter(
				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
				SecurityBizProperties bizProperties,
				SecurityQrcodeProperties qrcodeProperties,
				ObjectProvider<QrcodeAuthenticationProvider> qrcodeAuthenticationProvider,
				@Qualifier("jwtAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				@Qualifier("jwtAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
			
			this.bizProperties = bizProperties;
			this.qrcodeProperties = qrcodeProperties;
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			
			this.qrcodeAuthenticationProvider = qrcodeAuthenticationProvider.getIfAvailable();
			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

		@Bean
		public QrcodeAuthenticationProcessingFilter qrcodeAuthenticationProcessingFilter() throws Exception {
	    	
			QrcodeAuthenticationProcessingFilter authcFilter = new QrcodeAuthenticationProcessingFilter();

			authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
			authcFilter.setAuthenticationManager(authenticationManager);
			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
			authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
			if (StringUtils.hasText(qrcodeProperties.getAuthc().getLoginUrl())) {
				authcFilter.setFilterProcessesUrl(qrcodeProperties.getAuthc().getLoginUrl());
			}
			authcFilter.setPostOnly(qrcodeProperties.getAuthc().isPostOnly());
			authcFilter.setRememberMeServices(rememberMeServices);
			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
			
	        return authcFilter;
	    }
		
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) {
	        auth.authenticationProvider(qrcodeAuthenticationProvider);
	    }
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.addFilterBefore(qrcodeAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
		}

	}
	
}
