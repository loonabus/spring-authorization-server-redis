package io.doe.config;

import io.doe.common.Constants;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see BaseProperties
 * @since 2024-07-08
 */

public final class BaseProperties {

	private BaseProperties() {
		throw new UnsupportedOperationException(Constants.UNSUPPORTED_OPERATION_MESSAGE);
	}

	@Getter @Validated
	@ConfigurationProperties(prefix="base.auth")
	public static class Auth {

		@NotBlank private final String rcPath;
		@NotBlank private final String rsaPath;

		public Auth(final String rcPath, final String rsaPath) { this.rcPath = rcPath; this.rsaPath = rsaPath; }
	}
}
