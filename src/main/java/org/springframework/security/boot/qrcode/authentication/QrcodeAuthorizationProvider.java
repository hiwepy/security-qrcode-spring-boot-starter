package org.springframework.security.boot.qrcode.authentication;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.exception.AuthenticationTokenNotFoundException;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.qrcode.exception.AuthenticationQrcodeNotFoundException;
import org.springframework.security.boot.qrcode.userdetails.QrcodePrincipal;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import com.github.hiwepy.jwt.JwtPayload;

/**
 * 
 * Jwt授权 (authorization)处理器
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class QrcodeAuthorizationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final JwtPayloadRepository payloadRepository;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private boolean checkExpiry = false;
    private final UserDetailsServiceAdapter userDetailsService;
    
    public QrcodeAuthorizationProvider(final JwtPayloadRepository payloadRepository,
    		final UserDetailsServiceAdapter userDetailsService) {
        this.payloadRepository = payloadRepository;
        this.userDetailsService = userDetailsService;
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link JwtAuthenticationToken} 对象
     * @return 认证结果{@link JwtAuthenticationToken}对象
     * @throws AuthenticationException 认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
        String token = (String) authentication.getPrincipal();
		if (!StringUtils.hasText(token)) {
			logger.debug("No JWT found in request.");
			throw new AuthenticationTokenNotFoundException("No JWT found in request.");
		}
		
		String uuid = (String) authentication.getCredentials();
		if (!StringUtils.hasText(uuid)) {
			logger.debug("No Qrcode UUID found in request.");
			throw new AuthenticationQrcodeNotFoundException("No Qrcode UUID found in request.");
		}
		
		QrcodeAuthorizationToken authzToken = (QrcodeAuthorizationToken) authentication;
		
		// 解析Token载体信息
		JwtPayload payload = getPayloadRepository().getPayload(authzToken, checkExpiry);
		payload.setAccountNonExpired(true);
		payload.setAccountNonLocked(true);
		payload.setEnabled(true);
		payload.setCredentialsNonExpired(true);
		
		Set<GrantedAuthority> grantedAuthorities = new HashSet<GrantedAuthority>();
		
		// 角色必须是ROLE_开头，可以在数据库中设置
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_"+ payload.getRkey());
        grantedAuthorities.add(grantedAuthority);
   		
   		// 用户权限标记集合
        Set<String> perms = payload.getPerms();
		for (String perm : perms ) {
			GrantedAuthority authority = new SimpleGrantedAuthority(perm);
            grantedAuthorities.add(authority);
		}
		
		QrcodePrincipal principal = new QrcodePrincipal(payload.getClientId(), payload.getTokenId(), payload.isEnabled(),
				payload.isAccountNonExpired(), payload.isCredentialsNonExpired(), payload.isAccountNonLocked(),
				grantedAuthorities);
		
		principal.setUid(payload.getClientId());
		principal.setUuid(payload.getUuid());
		principal.setUkey(payload.getUkey());
		principal.setUcode(payload.getUcode());
		principal.setPerms(new HashSet<String>(perms));
		principal.setRid(payload.getRid());
		principal.setRkey(payload.getRkey());
		principal.setRoles(payload.getRoles());
		principal.setInitial(payload.isInitial());
		principal.setProfile(payload.getProfile());
		principal.setUuid(uuid);
		
        // User Status Check
        getUserDetailsChecker().check(principal);
          
        QrcodeAuthorizationToken authenticationToken = new QrcodeAuthorizationToken(principal, payload, principal.getAuthorities());        	
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (QrcodeAuthorizationToken.class.isAssignableFrom(authentication));
    }
    
	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}
    
}
