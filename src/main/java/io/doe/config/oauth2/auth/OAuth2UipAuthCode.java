package io.doe.config.oauth2.auth;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;

import java.time.Instant;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see OAuth2UipAuthCode
 * @since 2024-08-02
 */

public class OAuth2UipAuthCode extends AbstractOAuth2Token {

	public OAuth2UipAuthCode(final String tokenValue, final Instant issuedAt, final Instant expiresAt) {
		super(tokenValue, issuedAt, expiresAt);
	}
}
