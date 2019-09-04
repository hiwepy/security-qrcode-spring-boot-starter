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
package org.springframework.security.boot.qrcode;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class SecurityQrcodeAuthcProperties {

	public static final String PREFIX = "spring.security.jwt.authc";
	public static final String DEFAULT_CLAIMED_IDENTITY_FIELD = "openid_identifier";
	
	/** 登录地址：会话不存在时访问的地址 */
	private String loginUrl = "/authz/login";;
	private String loginUrlPatterns = "/login";;
	/** 重定向地址：会话注销后的重定向地址 */
	private String redirectUrl = "/";
	/** 系统主页：登录成功后跳转路径 */
	private String successUrl = "/index";;
	/** 未授权页面：无权限时的跳转路径 */
	private String unauthorizedUrl = "/error";
	/** 异常页面：认证失败时的跳转路径 */
	private String failureUrl = "/error";

	/** the regular expression for matching on OpenID's (i.e."https://www.google.com/.*", ".*yahoo.com.*", etc) */
	private String identifierPattern = "";
	
	/** The URL that determines if authentication is required */
	private String filterProcessesUrl;

	private boolean allowSessionCreation = true;
	/**
	 * The name of the request parameter containing the OpenID identity, as
	 * submitted from the initial login form. Defaults to "openid_identifier"
	 */
	private String claimedIdentityFieldName = DEFAULT_CLAIMED_IDENTITY_FIELD;

	/**
	 * Maps the <tt>return_to url</tt> to a realm, for example:
	 *
	 * <pre>
	 * http://www.example.com/login/openid -&gt; http://www.example.com/realm
	 * </pre>
	 *
	 * If no mapping is provided then the returnToUrl will be parsed to extract the
	 * protocol, hostname and port followed by a trailing slash. This means that
	 * <tt>http://www.example.com/login/openid</tt> will automatically become
	 * <tt>http://www.example.com:80/</tt>
	 */
	private Map<String, String> realmMapping = Collections.emptyMap();

	/**
	 * Specifies any extra parameters submitted along with the identity field which
	 * should be appended to the return_to URL which is assembled by
	 * buildReturnToUrl.
	 * <p>
	 * If not set, it will default to the parameter name used by the
	 * RememberMeServices obtained from the parent class (if one is set).
	 */
	private Set<String> returnToUrlParameters = Collections.emptySet();

	
	
	/** the username parameter name. Defaults to "username". */
	private String usernameParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;
	/** the password parameter name. Defaults to "password". */
	private String passwordParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	private boolean continueChainBeforeSuccessfulAuthentication = false;
	private boolean postOnly = true;
	private String retryTimesKeyParameter = AuthenticatingFailureCounter.DEFAULT_RETRY_TIMES_KEY_PARAM_NAME;
	private String retryTimesKeyAttribute = PostRequestAuthenticationProcessingFilter.DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME;
	/** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;
	private boolean useForward = false;
	
	public boolean isAllowSessionCreation() {
		return allowSessionCreation;
	}
	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}
	public String getFilterProcessesUrl() {
		return filterProcessesUrl;
	}
	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}
	public String getClaimedIdentityFieldName() {
		return claimedIdentityFieldName;
	}
	public void setClaimedIdentityFieldName(String claimedIdentityFieldName) {
		this.claimedIdentityFieldName = claimedIdentityFieldName;
	}
	public Map<String, String> getRealmMapping() {
		return realmMapping;
	}
	public void setRealmMapping(Map<String, String> realmMapping) {
		this.realmMapping = realmMapping;
	}
	public Set<String> getReturnToUrlParameters() {
		return returnToUrlParameters;
	}
	public void setReturnToUrlParameters(Set<String> returnToUrlParameters) {
		this.returnToUrlParameters = returnToUrlParameters;
	}
	public String getLoginUrl() {
		return loginUrl;
	}
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl; 
	}
	public String getLoginUrlPatterns() {
		return loginUrlPatterns;
	}
	public void setLoginUrlPatterns(String loginUrlPatterns) {
		this.loginUrlPatterns = loginUrlPatterns;
	}
	public String getRedirectUrl() {
		return redirectUrl;
	}
	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}
	public String getSuccessUrl() {
		return successUrl;
	}
	public void setSuccessUrl(String successUrl) {
		this.successUrl = successUrl;
	}
	public String getUnauthorizedUrl() {
		return unauthorizedUrl;
	}
	public void setUnauthorizedUrl(String unauthorizedUrl) {
		this.unauthorizedUrl = unauthorizedUrl;
	}
	public String getFailureUrl() {
		return failureUrl;
	}
	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}
	public String getIdentifierPattern() {
		return identifierPattern;
	}
	public void setIdentifierPattern(String identifierPattern) {
		this.identifierPattern = identifierPattern;
	}
	public String getUsernameParameter() {
		return usernameParameter;
	}
	public void setUsernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
	}
	public String getPasswordParameter() {
		return passwordParameter;
	}
	public void setPasswordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}
	public boolean isContinueChainBeforeSuccessfulAuthentication() {
		return continueChainBeforeSuccessfulAuthentication;
	}
	public void setContinueChainBeforeSuccessfulAuthentication(boolean continueChainBeforeSuccessfulAuthentication) {
		this.continueChainBeforeSuccessfulAuthentication = continueChainBeforeSuccessfulAuthentication;
	}
	public boolean isPostOnly() {
		return postOnly;
	}
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}
	public String getRetryTimesKeyParameter() {
		return retryTimesKeyParameter;
	}
	public void setRetryTimesKeyParameter(String retryTimesKeyParameter) {
		this.retryTimesKeyParameter = retryTimesKeyParameter;
	}
	public String getRetryTimesKeyAttribute() {
		return retryTimesKeyAttribute;
	}
	public void setRetryTimesKeyAttribute(String retryTimesKeyAttribute) {
		this.retryTimesKeyAttribute = retryTimesKeyAttribute;
	}
	public int getRetryTimesWhenAccessDenied() {
		return retryTimesWhenAccessDenied;
	}
	public void setRetryTimesWhenAccessDenied(int retryTimesWhenAccessDenied) {
		this.retryTimesWhenAccessDenied = retryTimesWhenAccessDenied;
	}
	public boolean isUseForward() {
		return useForward;
	}
	public void setUseForward(boolean useForward) {
		this.useForward = useForward;
	}
	
	

}
