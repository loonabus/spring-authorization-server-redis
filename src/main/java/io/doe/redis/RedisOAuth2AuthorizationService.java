package io.doe.redis;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.*;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see RedisOAuth2AuthorizationService
 * @since 2024-08-02
 */

public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService, RedisOperationProvider {

	private static final String ID_KEY_PREFIX = AUTH_KEY_PREFIX + "id:";
	private static final String TOKEN_KEY_PREFIX = AUTH_KEY_PREFIX + "token:";
	private static final Duration TOKEN_DATA_EXPIRATION_AFTER = Duration.ofDays(2);

	private final RedisTemplate<String, Object> redisTemplate;

	public RedisOAuth2AuthorizationService(final RedisTemplate<String, Object> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	@Override
	public void save(final OAuth2Authorization auth) {

		assertAuthorization(auth);

		redisTemplate.execute(new SessionCallback<>() {

			@Override @SuppressWarnings("unchecked")
			public Long execute(final RedisOperations ops) throws DataAccessException {

				ops.watch(ID_KEY_PREFIX + auth.getId()); ops.multi();
				ops.opsForValue().set(ID_KEY_PREFIX + auth.getId(), auth, TOKEN_DATA_EXPIRATION_AFTER);
				createOAuthTokenIndexesFrom(auth).forEach((k, v) -> ops.opsForValue().set(k, v, TOKEN_DATA_EXPIRATION_AFTER));

				return count(ops.exec());
			}
		});
	}

	@Override
	public void remove(final OAuth2Authorization auth) {

		assertAuthorization(auth);

		redisTemplate.execute(new SessionCallback<>() {

			@Override @SuppressWarnings("unchecked")
			public Long execute(final RedisOperations ops) throws DataAccessException {

				ops.watch(ID_KEY_PREFIX + auth.getId()); ops.multi();
				ops.delete(List.copyOf(createRemoveOAuthTokenKeysFrom(auth)));

				return count(ops.exec());
			}
		});
	}

	@Nullable
	@Override
	public OAuth2Authorization findById(final String id) {
		return getValue(ID_KEY_PREFIX + id);
	}

	@Nullable
	@Override
	public OAuth2Authorization findByToken(final String token, @Nullable final OAuth2TokenType type) {
		final String id = getValue(TOKEN_KEY_PREFIX + token);
		return StringUtils.hasText(id) ? checkUserProvidedTokenValidity(token, getValue(ID_KEY_PREFIX + id)) : null;
	}

	@Override
	public RedisTemplate<String, Object> getRedisTemplate() {
		return redisTemplate;
	}

	private void assertAuthorization(final OAuth2Authorization auth) {
		Assert.notNull(auth, "authorization cannot be null");
	}

	private Map<String, String> createOAuthTokenIndexesFrom(final OAuth2Authorization auth) {

		final Map<String, String> kv = new HashMap<>();

		final String state = auth.getAttribute(OAuth2ParameterNames.STATE);
		if (StringUtils.hasText(state)) { kv.put(TOKEN_KEY_PREFIX + state, auth.getId()); }

		final OAuth2Authorization.Token<OAuth2AuthorizationCode> code = auth.getToken(OAuth2AuthorizationCode.class);
		if (Objects.nonNull(code)) { kv.put(TOKEN_KEY_PREFIX + code.getToken().getTokenValue(), auth.getId()); }

		final OAuth2Authorization.Token<OidcIdToken> iToken = auth.getToken(OidcIdToken.class);
		if (Objects.nonNull(iToken)) { kv.put(TOKEN_KEY_PREFIX + iToken.getToken().getTokenValue(), auth.getId()); }

		final OAuth2Authorization.Token<OAuth2AccessToken> aToken = auth.getAccessToken();
		if (Objects.nonNull(aToken)) { kv.put(TOKEN_KEY_PREFIX + aToken.getToken().getTokenValue(), auth.getId()); }

		final OAuth2Authorization.Token<OAuth2RefreshToken> rToken = auth.getRefreshToken();
		if (Objects.nonNull(rToken)) { kv.put(TOKEN_KEY_PREFIX + rToken.getToken().getTokenValue(), auth.getId()); }

		final OAuth2Authorization.Token<OAuth2UserCode> uToken = auth.getToken(OAuth2UserCode.class);
		if (Objects.nonNull(uToken)) { kv.put(TOKEN_KEY_PREFIX + uToken.getToken().getTokenValue(), auth.getId()); }

		final OAuth2Authorization.Token<OAuth2DeviceCode> dToken = auth.getToken(OAuth2DeviceCode.class);
		if (Objects.nonNull(dToken)) { kv.put(TOKEN_KEY_PREFIX + dToken.getToken().getTokenValue(), auth.getId()); }

		return kv;
	}

	private List<String> createRemoveOAuthTokenKeysFrom(final OAuth2Authorization auth) {

		final List<String> ks = new ArrayList<>(List.of(ID_KEY_PREFIX + auth.getId()));

		Optional.ofNullable(auth.getAttribute(OAuth2ParameterNames.STATE)).filter(v -> StringUtils.hasText((String)v)).ifPresent(v -> ks.add(TOKEN_KEY_PREFIX + v));
		Optional.ofNullable(auth.getToken(OAuth2AuthorizationCode.class)).map(c -> c.getToken().getTokenValue()).ifPresent(v -> ks.add(TOKEN_KEY_PREFIX + v));
		Optional.ofNullable(auth.getToken(OidcIdToken.class)).map(c -> c.getToken().getTokenValue()).ifPresent(v -> ks.add(TOKEN_KEY_PREFIX + v));
		Optional.ofNullable(auth.getAccessToken()).map(c -> c.getToken().getTokenValue()).ifPresent(v -> ks.add(TOKEN_KEY_PREFIX + v));
		Optional.ofNullable(auth.getRefreshToken()).map(c -> c.getToken().getTokenValue()).ifPresent(v -> ks.add(TOKEN_KEY_PREFIX + v));
		Optional.ofNullable(auth.getToken(OAuth2UserCode.class)).map(c -> c.getToken().getTokenValue()).ifPresent(v -> ks.add(TOKEN_KEY_PREFIX + v));
		Optional.ofNullable(auth.getToken(OAuth2DeviceCode.class)).map(c -> c.getToken().getTokenValue()).ifPresent(v -> ks.add(TOKEN_KEY_PREFIX + v));

		return ks;
	}

	@Nullable
	private OAuth2Authorization checkUserProvidedTokenValidity(final String token, @Nullable final OAuth2Authorization auth) {

		if (Objects.isNull(auth)) { return null; }

		if (Objects.equals(token, auth.getAttribute(OAuth2ParameterNames.STATE))) { return auth; }

		final OAuth2Authorization.Token<OAuth2AuthorizationCode> code = auth.getToken(OAuth2AuthorizationCode.class);
		if (Objects.nonNull(code) && Objects.equals(token, code.getToken().getTokenValue())) { return auth; }

		final OAuth2Authorization.Token<OidcIdToken> iToken = auth.getToken(OidcIdToken.class);
		if (Objects.nonNull(iToken) && Objects.equals(token, iToken.getToken().getTokenValue())) { return auth; }

		final OAuth2Authorization.Token<OAuth2AccessToken> aToken = auth.getAccessToken();
		if (Objects.nonNull(aToken) && Objects.equals(token, aToken.getToken().getTokenValue())) { return auth; }

		final OAuth2Authorization.Token<OAuth2RefreshToken> rToken = auth.getRefreshToken();
		if (Objects.nonNull(rToken) && Objects.equals(token, rToken.getToken().getTokenValue())) { return auth; }

		final OAuth2Authorization.Token<OAuth2UserCode> uToken = auth.getToken(OAuth2UserCode.class);
		if (Objects.nonNull(uToken) && Objects.equals(token, uToken.getToken().getTokenValue())) { return auth; }

		final OAuth2Authorization.Token<OAuth2DeviceCode> dToken = auth.getToken(OAuth2DeviceCode.class);
		if (Objects.nonNull(dToken) && Objects.equals(token, dToken.getToken().getTokenValue())) { return auth; }

		return null;
	}
}
