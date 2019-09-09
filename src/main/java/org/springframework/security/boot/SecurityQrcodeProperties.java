package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.qrcode.SecurityQrcodeAuthzProperties;

@ConfigurationProperties(prefix = SecurityQrcodeProperties.PREFIX)
public class SecurityQrcodeProperties {

	public static final String PREFIX = "spring.security.qrcode";

	/** Whether Enable QrCode Authentication. */
	private boolean enabled = false;
	@NestedConfigurationProperty
	private SecurityQrcodeAuthzProperties authz = new SecurityQrcodeAuthzProperties();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public SecurityQrcodeAuthzProperties getAuthz() {
		return authz;
	}

	public void setAuthz(SecurityQrcodeAuthzProperties authz) {
		this.authz = authz;
	}

}
