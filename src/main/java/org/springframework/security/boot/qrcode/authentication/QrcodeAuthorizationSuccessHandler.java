/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.qrcode.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.qrcode.userdetails.QrcodePrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class QrcodeAuthorizationSuccessHandler implements AuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private final JwtPayloadRepository payloadRepository;
	private final StringRedisTemplate stringRedisTemplate;
	private final String EMPTY = "null";
	
	public QrcodeAuthorizationSuccessHandler(JwtPayloadRepository payloadRepository, StringRedisTemplate stringRedisTemplate) {
		this.payloadRepository = payloadRepository;
		this.stringRedisTemplate = stringRedisTemplate;
	}
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		QrcodePrincipal principal = (QrcodePrincipal) authentication.getPrincipal();
    	
		Map<String, Object> rtMap = new HashMap<String, Object>();
		rtMap.put("code", AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
		rtMap.put("msg", messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey()));
		
		// 账号首次登陆标记
		Map<String, Object> tokenMap = new HashMap<String, Object>(rtMap);
		
		tokenMap.put("initial", principal.isInitial());
		tokenMap.put("alias", StringUtils.hasText(principal.getAlias()) ? principal.getAlias() : EMPTY);
		tokenMap.put("usercode", StringUtils.hasText(principal.getUsercode()) ? principal.getUsercode() : EMPTY);
		tokenMap.put("userkey", StringUtils.hasText(principal.getUserkey()) ? principal.getUserkey() : EMPTY);
		tokenMap.put("userid", StringUtils.hasText(principal.getUserid()) ? principal.getUserid() : EMPTY);
		tokenMap.put("roleid", StringUtils.hasText(principal.getRoleid()) ? principal.getRoleid() : EMPTY );
		tokenMap.put("role", StringUtils.hasText(principal.getRole()) ? principal.getRole() : EMPTY);
		tokenMap.put("roles", CollectionUtils.isEmpty(principal.getRoles()) ? new ArrayList<>() : principal.getRoles() );
		tokenMap.put("restricted", principal.isRestricted());
		tokenMap.put("profile", CollectionUtils.isEmpty(principal.getProfile()) ? new HashMap<>() : principal.getProfile() );
		tokenMap.put("faced", principal.isFace());
		tokenMap.put("faceId", StringUtils.hasText(principal.getFaceId()) ? principal.getFaceId() : EMPTY );
		
		tokenMap.put("perms", principal.getAuthorities());
		tokenMap.put("token", getPayloadRepository().issueJwt((AbstractAuthenticationToken) authentication));
		tokenMap.put("username", principal.getUsername());
		
		// 设置UUID对应的登录信息
		getStringRedisTemplate().opsForValue().set(String.format("login-%s", principal.getUuid()), JSONObject.toJSONString(tokenMap), Duration.ofMinutes(1));
		
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		
		JSONObject.writeJSONString(response.getWriter(), rtMap);
		
		clearAuthenticationAttributes(request);
				
	}
	
	/**
	 * Removes temporary authentication-related data which may have been stored in the
	 * session during the authentication process.
	 */
	protected final void clearAuthenticationAttributes(HttpServletRequest request) {
		HttpSession session = request.getSession(false);

		if (session == null) {
			return;
		}

		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}


	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	public StringRedisTemplate getStringRedisTemplate() {
		return stringRedisTemplate;
	}
	
}
