package org.springframework.security.boot.qrcode.authentication;

import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.qrcode.exception.AuthenticationQrcodeNotFoundException;
import org.springframework.security.boot.qrcode.userdetails.QrcodeInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

public class QrcodeAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final QrcodeRecognitionProvider faceRecognitionProvider;
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    public QrcodeAuthenticationProvider(final QrcodeRecognitionProvider faceRecognitionProvider,
    		final UserDetailsServiceAdapter userDetailsService) {
    	this.faceRecognitionProvider = faceRecognitionProvider;
        this.userDetailsService = userDetailsService;
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/vindell">wandl</a>
     * @param authentication  {@link QrcodeAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
    	InputStream faceStream = (InputStream) authentication.getPrincipal();
        if (faceStream == null) {
			logger.debug("No principal found in request.");
			throw new BadCredentialsException("No principal found in request.");
		}
        
        // load face info by face image
        QrcodeInfo faceInfo = getFaceRecognitionProvider().loadFaceInfo(authentication);
        if (faceInfo == null) {
			logger.debug("No Qrcode info found by face image.");
			throw new AuthenticationQrcodeNotFoundException("No face info found by face image.");
		}
        
        // load user details by face info
		UserDetails ud = getUserDetailsService().loadUserDetails(new QrcodeAuthenticationToken(faceInfo));
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        QrcodeAuthenticationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	authenticationToken = new QrcodeAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new QrcodeAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (QrcodeAuthenticationToken.class.isAssignableFrom(authentication));
    }

	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public QrcodeRecognitionProvider getFaceRecognitionProvider() {
		return faceRecognitionProvider;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}
