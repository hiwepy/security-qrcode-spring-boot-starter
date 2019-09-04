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
package org.springframework.security.boot.qrcode.userdetails;

import java.util.Collection;

import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.GrantedAuthority;

/**
 * TODO
 * 
 * @author ： <a href="https://github.com/vindell">wandl</a>
 */
@SuppressWarnings("serial")
public class QrcodePrincipal extends SecurityPrincipal {

	/**
	 * 人脸识别数据ID
	 */
	protected String faceId;
	/**
	 * 人脸识别图片base64编码后的图片数据（图片的base64编码不包含图片头的，如data:image/jpg;base64,）
	 */
	protected String face;
	/**
	 * 人脸的类型：(LIVE:表示生活照;通常为手机、相机拍摄的人像图片、或从网络获取的人像图片等|IDCARD:表示身份证芯片照;二代身份证内置芯片中的人像照片|WATERMARK:表示带水印证件照;一般为带水印的小图，如公安网小图|CERT:表示证件照片;如拍摄的身份证、工卡、护照、学生证等证件图片); 默认LIVE
	 */
	protected String faceType;
	/**
	 * 人脸图片的唯一标识
	 */
	protected String faceToken;

	public QrcodePrincipal(String username, String password, String... roles) {
		super(username, password, roles);
	}

	public QrcodePrincipal(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	public QrcodePrincipal(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
	}

	public String getFaceId() {
		return faceId;
	}

	public void setFaceId(String faceId) {
		this.faceId = faceId;
	}

	public String getFace() {
		return face;
	}

	public void setFace(String face) {
		this.face = face;
	}

	public String getFaceType() {
		return faceType;
	}

	public void setFaceType(String faceType) {
		this.faceType = faceType;
	}

	public String getFaceToken() {
		return faceToken;
	}

	public void setFaceToken(String faceToken) {
		this.faceToken = faceToken;
	}

}
