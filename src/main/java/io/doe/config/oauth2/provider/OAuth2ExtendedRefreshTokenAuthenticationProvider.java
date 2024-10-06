package io.doe.config.oauth2.provider;

import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.Principal;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see OAuth2ExtendedRefreshTokenAuthenticationProvider
 * @since 2024-07-20
 * this implementation is to synchronize the token creation process with customized 'access token' creation process
 */

@Slf4j
public class OAuth2ExtendedRefreshTokenAuthenticationProvider implements AuthenticationProvider {

	private static final OAuth2AuthenticationException INVALID_GRANT_EXCEPTION;

	static {
		INVALID_GRANT_EXCEPTION = new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
	}

	private final OAuth2AuthorizationService oAuth2;
	private final OAuth2TokenGenerator<? extends OAuth2Token> generator;

	public OAuth2ExtendedRefreshTokenAuthenticationProvider(final OAuth2AuthorizationService oAuth2, final OAuth2TokenGenerator<? extends OAuth2Token> generator) {
		this.oAuth2 = oAuth2; this.generator = generator;
	}

	@Override
	public Authentication authenticate(final Authentication auth) throws AuthenticationException {

		final OAuth2RefreshTokenAuthenticationToken raToken = (OAuth2RefreshTokenAuthenticationToken)auth;
		final OAuth2ClientAuthenticationToken caToken = AbstractOAuth2AuthTokenProvider.ExtendedTokenGenerator.retrieveOAuth2ClientAuthenticationToken(raToken);
		final RegisteredClient rc = caToken.getRegisteredClient();

		final OAuth2Authorization authorization = oAuth2.findByToken(raToken.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
		final Set<String> scopes = retrieveScopesAfterCheckClientValidityAndThrowException(authorization, rc, raToken);
		final OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(Objects.requireNonNull(authorization));

		final DefaultOAuth2TokenContext.Builder builder = DefaultOAuth2TokenContext.builder().registeredClient(rc)
				.principal(Objects.requireNonNull(authorization).getAttribute(Principal.class.getName())).authorization(authorization)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext()).authorizedScopes(scopes).authorizationGrant(raToken).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);

		final OAuth2TokenContext context = builder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		final OAuth2AccessToken aToken = AbstractOAuth2AuthTokenProvider.ExtendedTokenGenerator.createOAuth2AccessToken(context, generator, authorizationBuilder);
		final Optional<OAuth2RefreshToken> rToken = AbstractOAuth2AuthTokenProvider.ExtendedTokenGenerator.createOAuth2RefreshToken(Objects.requireNonNull(rc), generator, builder);

		rToken.ifPresent(authorizationBuilder::refreshToken);
		oAuth2.save(authorizationBuilder.build());

		log.trace("Saved authorization with newly create token information");
		log.trace("Authenticated token request using {}", AuthorizationGrantType.REFRESH_TOKEN.getValue().toLowerCase());

		return new OAuth2AccessTokenAuthenticationToken(rc, caToken, aToken, rToken.orElse(null), Map.of());
	}

	@Override
	public boolean supports(final Class<?> auth) {
		return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(auth);
	}

	private Set<String> retrieveScopesAfterCheckClientValidityAndThrowException(
			@Nullable final OAuth2Authorization oAuth2Auth, @Nullable final RegisteredClient rc, final OAuth2RefreshTokenAuthenticationToken raToken) {

		if (Objects.isNull(oAuth2Auth)) {
			log.debug("Invalid request: refreshToken is invalid");
			throw INVALID_GRANT_EXCEPTION;
		}
		if (Objects.isNull(rc) || !rc.getId().equals(oAuth2Auth.getRegisteredClientId())) {
			throw INVALID_GRANT_EXCEPTION;
		}
		if (!rc.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			log.debug("Invalid request: requested grant_type is not allowed for registered client {}", rc.getId());
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		final OAuth2Authorization.Token<OAuth2RefreshToken> rTokenFromRepo = oAuth2Auth.getRefreshToken();
		if (Objects.isNull(rTokenFromRepo) || !rTokenFromRepo.isActive()) {
			log.debug("Invalid request: refreshToken is not active for registered client {}", rc.getId());
			throw INVALID_GRANT_EXCEPTION;
		}

		final Set<String> scopes = raToken.getScopes();
		final Set<String> authorized = oAuth2Auth.getAuthorizedScopes();
		if (!authorized.containsAll(scopes)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
		}

		return Set.copyOf(scopes.isEmpty() ? authorized : scopes);
	}
}
