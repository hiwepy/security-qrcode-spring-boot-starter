package org.springframework.security.boot.qrcode.authentication;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.qrcode.userdetails.QrcodePrincipal;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * 二维码扫码认证 (authentication)成功回调器：认证信息写入Redis缓存
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class QrcodeMatchedAuthenticationSuccessHandler implements MatchedAuthenticationSuccessHandler {
   
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private final JwtPayloadRepository payloadRepository;
	private final StringRedisTemplate stringRedisTemplate;
	private final String EMPTY = "null";
	
	public QrcodeMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository, StringRedisTemplate stringRedisTemplate) {
		this.payloadRepository = payloadRepository;
		this.stringRedisTemplate = stringRedisTemplate;
	}
	
	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.isAssignableFrom(authentication.getClass(), QrcodeAuthenticationToken.class);
	}

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        
    	UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    	
		Map<String, Object> rtMap = new HashMap<String, Object>();
		rtMap.put("code", AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
		rtMap.put("msg", messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey()));
		
		// 账号首次登陆标记
		if(QrcodePrincipal.class.isAssignableFrom(userDetails.getClass())) {
			
			QrcodePrincipal securityPrincipal = (QrcodePrincipal) userDetails;
			
			Map<String, Object> tokenMap = new HashMap<String, Object>(rtMap);
			
			tokenMap.put("initial", securityPrincipal.isInitial());
			tokenMap.put("alias", StringUtils.hasText(securityPrincipal.getAlias()) ? securityPrincipal.getAlias() : EMPTY);
			tokenMap.put("usercode", StringUtils.hasText(securityPrincipal.getUsercode()) ? securityPrincipal.getUsercode() : EMPTY);
			tokenMap.put("userkey", StringUtils.hasText(securityPrincipal.getUserkey()) ? securityPrincipal.getUserkey() : EMPTY);
			tokenMap.put("userid", StringUtils.hasText(securityPrincipal.getUserid()) ? securityPrincipal.getUserid() : EMPTY);
			tokenMap.put("roleid", StringUtils.hasText(securityPrincipal.getRoleid()) ? securityPrincipal.getRoleid() : EMPTY );
			tokenMap.put("role", StringUtils.hasText(securityPrincipal.getRole()) ? securityPrincipal.getRole() : EMPTY);
			tokenMap.put("roles", CollectionUtils.isEmpty(securityPrincipal.getRoles()) ? new ArrayList<>() : securityPrincipal.getRoles() );
			tokenMap.put("restricted", securityPrincipal.isRestricted());
			tokenMap.put("profile", CollectionUtils.isEmpty(securityPrincipal.getProfile()) ? new HashMap<>() : securityPrincipal.getProfile() );
			tokenMap.put("faced", securityPrincipal.isFace());
			tokenMap.put("faceId", StringUtils.hasText(securityPrincipal.getFaceId()) ? securityPrincipal.getFaceId() : EMPTY );
			
			tokenMap.put("perms", userDetails.getAuthorities());
			tokenMap.put("token", getPayloadRepository().issueJwt((AbstractAuthenticationToken) authentication));
			tokenMap.put("username", userDetails.getUsername());
			
			// 设置UUID对应的登录信息
			getStringRedisTemplate().opsForValue().set(String.format("login-%s", securityPrincipal.getUuid()), JSONObject.toJSONString(tokenMap), Duration.ofMinutes(1));
			
		}
		
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
		JSONObject.writeJSONString(response.getWriter(), rtMap);
    	
    }
    
	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	public StringRedisTemplate getStringRedisTemplate() {
		return stringRedisTemplate;
	}

}
