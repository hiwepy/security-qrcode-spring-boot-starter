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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.biz.exception.AuthenticationTokenNotFoundException;
import org.springframework.security.boot.qrcode.exception.AuthenticationQrcodeNotFoundException;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * 二维码扫码登录授权 (authorization)过滤器
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class QrcodeAuthorizationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	public static final String AUTHORIZATION_PARAM = "token";
	public static final String QRCODE_UUID_PARAM = "uuid";
   
	/**
	 * HTTP Authorization header, equal to <code>Authorization</code>
	 */
	public static final String AUTHORIZATION_HEADER = "X-Authorization";

	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	private String authorizationParamName = AUTHORIZATION_PARAM;
	private String authorizationCookieName = AUTHORIZATION_PARAM;
	private String qrcodeParameter = QRCODE_UUID_PARAM;
	
	private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();
	
	public QrcodeAuthorizationProcessingFilter() {
		super(new AntPathRequestMatcher("/login/qrcode"));
	}
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
 
		if (!requiresAuthentication(request, response)) {
			chain.doFilter(request, response);
			return;
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("Request is to process authentication");
		}

		Authentication authResult;

		try {
			authResult = attemptAuthentication(request, response);
			if (authResult == null) {
				// return immediately as subclass has indicated that it hasn't completed
				// authentication
				return;
			}
			sessionStrategy.onAuthentication(authResult, request, response);
		}
		catch (InternalAuthenticationServiceException failed) {
			logger.error(
					"An internal error occurred while trying to authenticate the user.",
					failed);
			unsuccessfulAuthentication(request, response, failed);

			return;
		}
		catch (AuthenticationException failed) {
			// Authentication failed
			unsuccessfulAuthentication(request, response, failed);

			return;
		}
		
		successfulAuthentication(request, response, chain, authResult);
		
	}
	
	@Override
	public void setSessionAuthenticationStrategy(
			SessionAuthenticationStrategy sessionStrategy) {
		super.setSessionAuthenticationStrategy(sessionStrategy);
		this.sessionStrategy = sessionStrategy;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {


    	String uuid = obtainUuid(request);

        if (uuid == null) {
        	uuid = "";
        }
        
        uuid = uuid.trim();
        
        if(!StringUtils.hasText(uuid)) {
			logger.debug("Qrcode UUID not provided.");
			throw new AuthenticationQrcodeNotFoundException("Qrcode UUID not provided.");
		}
        
		String token = obtainToken(request);

		if (token == null) {
			token = "";
		}

		token = token.trim();
		
		if(!StringUtils.hasText(token)) {
			throw new AuthenticationTokenNotFoundException("JWT not provided");
		}

        AbstractAuthenticationToken authRequest = this.authenticationToken(token, uuid);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
        
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	/**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	protected AbstractAuthenticationToken authenticationToken(String token, String uuid) {
		return new QrcodeAuthorizationToken( token, uuid );
	}
	
	protected String obtainToken(HttpServletRequest request) {

		// 从header中获取token
		String token = request.getHeader(getAuthorizationHeaderName());
		// 如果header中不存在token，则从参数中获取token
		if (StringUtils.isEmpty(token)) {
			return request.getParameter(getAuthorizationParamName());
		}
		if (StringUtils.isEmpty(token)) {
			// 从 cookie 获取 token
			Cookie[] cookies = request.getCookies();
			if (null == cookies || cookies.length == 0) {
				return null;
			}
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(getAuthorizationCookieName())) {
					token = cookie.getValue();
					break;
				}
			}
		}
		return token;
	}
	
	protected String obtainUuid(HttpServletRequest request) {
        return request.getParameter(getQrcodeParameter());
    }
	
	public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}

	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

	public String getAuthorizationCookieName() {
		return authorizationCookieName;
	}

	public void setAuthorizationCookieName(String authorizationCookieName) {
		this.authorizationCookieName = authorizationCookieName;
	}

	public String getQrcodeParameter() {
		return qrcodeParameter;
	}

	public void setQrcodeParameter(String qrcodeParameter) {
		this.qrcodeParameter = qrcodeParameter;
	}

	public SessionAuthenticationStrategy getSessionStrategy() {
		return sessionStrategy;
	}

	public void setSessionStrategy(SessionAuthenticationStrategy sessionStrategy) {
		this.sessionStrategy = sessionStrategy;
	}

}