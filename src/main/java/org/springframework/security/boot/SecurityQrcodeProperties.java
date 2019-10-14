package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityQrcodeProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityQrcodeProperties {

	public static final String PREFIX = "spring.security.qrcode";

	/** Whether Enable QrCode Authentication. */
	private boolean enabled = false;

}
