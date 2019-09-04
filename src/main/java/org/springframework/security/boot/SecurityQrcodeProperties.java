package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.qrcode.SecurityQrcodeAuthcProperties;

@ConfigurationProperties(prefix = SecurityQrcodeProperties.PREFIX)
public class SecurityQrcodeProperties {

	public static final String PREFIX = "spring.security.qrcode";

	/** Whether Enable QrCode Authentication. */
	private boolean enabled = false;
	@NestedConfigurationProperty
	private SecurityQrcodeAuthcProperties authc = new SecurityQrcodeAuthcProperties();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public SecurityQrcodeAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityQrcodeAuthcProperties authc) {
		this.authc = authc;
	}

}
