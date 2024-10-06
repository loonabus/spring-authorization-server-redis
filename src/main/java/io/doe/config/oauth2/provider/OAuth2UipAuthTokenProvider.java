package io.doe.config.oauth2.provider;

import io.doe.config.oauth2.auth.OAuth2UipAuthCode;
import io.doe.config.oauth2.auth.OAuth2UipAuthToken;
import io.doe.config.oauth2.converter.AbstractOAuth2AuthConverter;
import io.doe.domain.User;
import io.doe.service.UserService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Duration;
import java.time.Instant;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see OAuth2UipAuthTokenProvider
 * @since 2024-07-20
 */

public class OAuth2UipAuthTokenProvider extends AbstractOAuth2AuthTokenProvider<OAuth2UipAuthToken> {

	private static final AuthorizationGrantType GRANT_TYPE = AbstractOAuth2AuthConverter.CustomGrantTypes.from(AbstractOAuth2AuthConverter.CustomGrantTypes.UIP);

	private final UserService service;

	public OAuth2UipAuthTokenProvider(final PasswordEncoder encoder, final RegisteredClientRepository repo,
			final OAuth2AuthorizationService oAuth2, final OAuth2TokenGenerator<? extends OAuth2Token> generator, final UserService service) {
		super(encoder, repo, oAuth2, generator); this.service = service;
	}

	@Override
	User retrieveUser(final OAuth2UipAuthToken auth) {

		try {
			final User user = service.retrieveUser(auth.getId());
			if (unmatched(auth.getPw(), user.getPassword())) { throw new UsernameNotFoundException("user not found"); }

			return user;
		} catch (final UsernameNotFoundException e) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "user not found", e);
		}
	}

	@Override
	AbstractOAuth2Token createAuthorizationToken(final OAuth2UipAuthToken auth) {
		return new OAuth2UipAuthCode(auth.getCode(), Instant.now(), Instant.now().plus(Duration.ofMinutes(1)));
	}

	@Override
	AuthorizationGrantType retrieveSupportedGrantType() {
		return GRANT_TYPE;
	}

	@Override
	public boolean supports(final Class<?> authentication) {
		return OAuth2UipAuthToken.class.isAssignableFrom(authentication);
	}
}
