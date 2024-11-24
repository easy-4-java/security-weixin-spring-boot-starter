package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityWxProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityWxProperties {

	public static final String PREFIX = "spring.security.weixin";

	/** Whether Enable WeiXin Authentication. */
	private boolean enabled = false;

}
