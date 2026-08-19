package org.springframework.security.boot.qrcode.authentication;

import io.github.easy4j.jwt.JwtPayload;
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

import java.util.HashSet;
import java.util.Set;

/**
 *
 * Jwt授权 (authorization)处理器
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class QrcodeAuthorizationProvider implements AuthenticationProvider {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final JwtPayloadRepository payloadRepository;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private boolean checkExpiry = false;
    private final UserDetailsServiceAdapter userDetailsService;

    /**
     * Constructs a new qrcode authorization provider instance.
     *
     * @param payloadRepository the payload repository
     * @param userDetailsService the user details service
     */
    public QrcodeAuthorizationProvider(final JwtPayloadRepository payloadRepository,
    		final UserDetailsServiceAdapter userDetailsService) {
        this.payloadRepository = payloadRepository;
        this.userDetailsService = userDetailsService;
    }

    /**
     *
     * 完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中
     * @author <a href="https://github.com/loong10k">Loong Wan</a>
     * @param authentication  {@link QrcodeAuthorizationToken} 对象
     * @return 认证结果{@link QrcodeAuthorizationToken}对象
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

		QrcodePrincipal principal = new QrcodePrincipal(payload.getSubject(), payload.getTokenId(), payload.isEnabled(),
				payload.isAccountNonExpired(), payload.isCredentialsNonExpired(), payload.isAccountNonLocked(),
				grantedAuthorities);

		principal.setUid(payload.getSubject());
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

    /**
     * Determines whether supports.
     *
     * @param authentication the authentication
     * @return the result
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (QrcodeAuthorizationToken.class.isAssignableFrom(authentication));
    }

	/**
	 * Returns the user details service.
	 *
	 * @return the user details service
	 */
	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}

    /**
     * Sets the user details checker.
     *
     * @param userDetailsChecker the user details checker
     */
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	/**
	 * Returns the user details checker.
	 *
	 * @return the user details checker
	 */
	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	/**
	 * Returns the payload repository.
	 *
	 * @return the payload repository
	 */
	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	/**
	 * Returns the check expiry.
	 *
	 * @return the check expiry
	 */
	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	/**
	 * Sets the check expiry.
	 *
	 * @param checkExpiry the check expiry
	 */
	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

}
