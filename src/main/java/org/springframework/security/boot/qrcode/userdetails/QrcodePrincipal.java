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
	 * 二维码UUID
	 */
	protected String uuid;

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

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

}
