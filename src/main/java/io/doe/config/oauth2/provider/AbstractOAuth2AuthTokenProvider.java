package io.doe.config.oauth2.provider;

import io.doe.common.Constants;
import io.doe.config.oauth2.auth.OAuthCustomAuthToken;
import io.doe.domain.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see AbstractOAuth2AuthTokenProvider
 * @since 2024-07-20
 */

@Slf4j
public abstract class AbstractOAuth2AuthTokenProvider<U extends Authentication> implements AuthenticationProvider {

	private final PasswordEncoder encoder;
	private final OAuth2AuthorizationService oAuth2;
	private final RegisteredClientRepository repo;
	private final OAuth2TokenGenerator<? extends OAuth2Token> generator;

	protected AbstractOAuth2AuthTokenProvider(final PasswordEncoder encoder, final RegisteredClientRepository repo,
			final OAuth2AuthorizationService oAuth2, final OAuth2TokenGenerator<? extends OAuth2Token> generator) {
		this.encoder = encoder; this.oAuth2 = oAuth2; this.repo = repo; this.generator = generator;
	}

	@Override
	@SuppressWarnings("unchecked")
	public Authentication authenticate(final Authentication auth) throws AuthenticationException {

		final OAuth2ClientAuthenticationToken caToken = ExtendedTokenGenerator.retrieveOAuth2ClientAuthenticationToken(auth);
		final RegisteredClient rc = retrieveRegisteredClientAndThrowIfUnmatched(caToken, ((auth instanceof OAuthCustomAuthToken o) ? o.getScope() : Set.of()));

		final User user = retrieveUser((U)auth);
		final UsernamePasswordAuthenticationToken upToken = UsernamePasswordAuthenticationToken.authenticated(user, user.getPassword(), user.getAuthorities());

		final OAuth2Authorization authorization = OAuth2Authorization
				.withRegisteredClient(Objects.requireNonNull(rc))
				.principalName(user.getUsername()).attribute(Principal.class.getName(), upToken)
				.authorizedScopes(rc.getScopes()).authorizationGrantType(retrieveSupportedGrantType())
				.token(createAuthorizationToken((U)auth)).build();

		final OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
		final Set<String> combinedScopeAuthorities = Stream.concat(authorization.getAuthorizedScopes().stream(),
				user.getAuthorities().stream().map(GrantedAuthority::getAuthority)).collect(Collectors.toSet());
		authorizationBuilder.authorizedScopes(combinedScopeAuthorities);

		final DefaultOAuth2TokenContext.Builder builder = DefaultOAuth2TokenContext.builder()
				.registeredClient(rc).principal(upToken).authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization).authorizedScopes(combinedScopeAuthorities).authorizationGrant(auth).authorizationGrantType(retrieveSupportedGrantType());

		final OAuth2TokenContext context = builder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		final OAuth2AccessToken aToken = ExtendedTokenGenerator.createOAuth2AccessToken(context, generator, authorizationBuilder);
		final Optional<OAuth2RefreshToken> rToken = ExtendedTokenGenerator.createOAuth2RefreshToken(rc, generator, builder);

		rToken.ifPresent(authorizationBuilder::refreshToken);
		oAuth2.save(authorizationBuilder.build());

		log.trace("Saved authorization with newly create token information");
		log.trace("Authenticated token request using {}", retrieveSupportedGrantType().getValue());

		return new OAuth2AccessTokenAuthenticationToken(rc, caToken, aToken, rToken.orElse(null), Map.of());
	}

	abstract User retrieveUser(final U auth);
	abstract AuthorizationGrantType retrieveSupportedGrantType();
	abstract AbstractOAuth2Token createAuthorizationToken(final U auth);

	boolean unmatched(@Nullable final String raw, @Nullable final String encoded) {
		return !encoder.matches(raw, encoded);
	}

	private RegisteredClient retrieveRegisteredClientAndThrowIfUnmatched(final OAuth2ClientAuthenticationToken caToken, final Set<String> source) {

		final RegisteredClient fromToken = caToken.getRegisteredClient();
		if (Objects.isNull(fromToken) || !fromToken.getAuthorizationGrantTypes().contains(retrieveSupportedGrantType())) {
			log.trace("Invalid request: grant type not allowed for client {}", Objects.nonNull(fromToken) ? fromToken.getId() : "unknown");
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		final RegisteredClient fromRepo = repo.findByClientId(fromToken.getClientId());
		if (Objects.isNull(fromRepo)) {
			log.trace("Invalid request: client id not found from repo : {}", fromToken.getClientId());
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		final Object credentials = caToken.getCredentials();
		if (Objects.isNull(credentials) || unmatched(credentials.toString(), fromRepo.getClientSecret())) {
			log.trace("Invalid request: client secret not matched for client {}", fromToken.getClientId());
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		final Set<String> scope = source.isEmpty() ? fromToken.getScopes() : source;
		if (CollectionUtils.isEmpty(scope) || !fromRepo.getScopes().containsAll(scope)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
		}

		return RegisteredClient.from(fromToken).scopes(s -> s.removeIf(e -> !scope.contains(e))).build();
	}


	static final class ExtendedTokenGenerator {

		private ExtendedTokenGenerator() {
			throw new UnsupportedOperationException(Constants.UNSUPPORTED_OPERATION_MESSAGE);
		}

		static OAuth2ClientAuthenticationToken retrieveOAuth2ClientAuthenticationToken(final Authentication auth) {

			if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(auth.getPrincipal().getClass())) {
				final OAuth2ClientAuthenticationToken principal = (OAuth2ClientAuthenticationToken)auth.getPrincipal();
				if (Objects.nonNull(principal) && principal.isAuthenticated()) { return principal; }
			}

			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		static OAuth2AccessToken createOAuth2AccessToken(final OAuth2TokenContext context,
				final OAuth2TokenGenerator<? extends OAuth2Token> generator, final OAuth2Authorization.Builder builder) {

			final OAuth2Token source = Optional.ofNullable(generator.generate(context))
					.orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "failed to generate the access token", "")));
			final OAuth2AccessToken aToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, source.getTokenValue(), source.getIssuedAt(), source.getExpiresAt(), context.getAuthorizedScopes());

			builder.token(aToken, m -> {
				if (source instanceof ClaimAccessor accessor) {
					m.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, accessor.getClaims());
				}

				m.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
				m.put(OAuth2TokenFormat.class.getName(), context.getRegisteredClient().getTokenSettings().getAccessTokenFormat().getValue());
			});

			return aToken;
		}

		static Optional<OAuth2RefreshToken> createOAuth2RefreshToken(final RegisteredClient client,
				final OAuth2TokenGenerator<? extends OAuth2Token> generator, final DefaultOAuth2TokenContext.Builder builder) {

			if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
				final OAuth2Token source = generator.generate(builder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build());
				final OAuth2Token refreshToken = Optional.ofNullable(source).orElseThrow(() ->
						new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "failed to generate refresh token", "")));

				return Optional.of((OAuth2RefreshToken)refreshToken);
			}

			return Optional.empty();
		}
	}
}
