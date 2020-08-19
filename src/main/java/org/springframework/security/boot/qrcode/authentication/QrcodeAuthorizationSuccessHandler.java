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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.boot.qrcode.userdetails.QrcodePrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.alibaba.fastjson.JSONObject;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class QrcodeAuthorizationSuccessHandler implements AuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private final JwtPayloadRepository payloadRepository;
	private final StringRedisTemplate stringRedisTemplate;
	private boolean checkExpiry = false;
	
	public QrcodeAuthorizationSuccessHandler(JwtPayloadRepository payloadRepository, StringRedisTemplate stringRedisTemplate) {
		this.payloadRepository = payloadRepository;
		this.stringRedisTemplate = stringRedisTemplate;
	}
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		UserProfilePayload profilePayload = getPayloadRepository().getProfilePayload((AbstractAuthenticationToken) authentication, isCheckExpiry());
		
    	UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		if(QrcodePrincipal.class.isAssignableFrom(userDetails.getClass())) {
			QrcodePrincipal principal = (QrcodePrincipal) userDetails;
			// 设置UUID对应的登录信息
			getStringRedisTemplate().opsForValue().set(String.format("login-%s", principal.getUuid()), JSONObject.toJSONString(profilePayload), Duration.ofMinutes(1));
		}
		
		// 设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		// 国际化后的异常信息
		String message = messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey(), LocaleContextHolder.getLocale());
		// 写出JSON
		JSONObject.writeJSONString(response.getWriter(), AuthResponse.success(message, profilePayload));
		
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
	

	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}
	
}
