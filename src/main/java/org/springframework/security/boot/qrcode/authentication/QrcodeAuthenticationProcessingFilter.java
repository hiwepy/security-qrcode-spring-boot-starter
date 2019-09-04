/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationMethodNotSupportedException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class QrcodeAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	public static final String SPRING_SECURITY_FORM_QRCODE_KEY = "qrcode";

    private String qrcodeParameter = SPRING_SECURITY_FORM_QRCODE_KEY;
    private boolean postOnly = true;
	
    public QrcodeAuthenticationProcessingFilter() {
    	super(new AntPathRequestMatcher("/login/qrcode", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        if (isPostOnly() && !WebUtils.isPostRequest(request) ) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method not supported. Request method: " + request.getMethod());
			}
			throw new AuthenticationMethodNotSupportedException(messages.getMessage(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getMsgKey(), new Object[] { request.getMethod() }, 
					"Authentication method not supported. Request method:" + request.getMethod()));
		}
        

    	String uuid = obtainUuid(request);

        if (uuid == null) {
        	uuid = "";
        }
 		
        AbstractAuthenticationToken authRequest = this.authenticationToken(uuid);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);

    }

	protected AbstractAuthenticationToken authenticationToken(String uuid) {
		return new QrcodeAuthenticationToken( uuid );
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
	
	protected String obtainUuid(HttpServletRequest request) {
        return request.getParameter(getQrcodeParameter());
    }
	
	public String getQrcodeParameter() {
		return qrcodeParameter;
	}

	public void setQrcodeParameter(String qrcodeParameter) {
		this.qrcodeParameter = qrcodeParameter;
	}

	public boolean isPostOnly() {
		return postOnly;
	}

	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

}