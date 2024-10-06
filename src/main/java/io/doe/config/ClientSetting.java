package io.doe.config;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import io.doe.common.Constants;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.Assert;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see ClientSetting
 * @since 2024-08-01
 */

class ClientSetting {

	private static final String REGISTERED_CLIENT_FILE_PATH = "classpath:rc/rc";

	private ClientSetting() {
		throw new UnsupportedOperationException(Constants.UNSUPPORTED_OPERATION_MESSAGE);
	}

	record ClientInfo(String id, String client, String secret, Set<String> methods,
			Set<String> grantTypes, Set<String> scopes, Integer aTokenMinutes, Integer rTokenMinutes, String redirectUri) {

		void executeAsserts() {
			Assert.hasText(id, "id cannot be null");
			Assert.hasText(client, "client cannot be null");
			Assert.hasText(secret, "secret cannot be null");
			Assert.notEmpty(methods, "methods cannot be empty");
			Assert.notEmpty(grantTypes, "grantTypes cannot be empty");
			Assert.notEmpty(scopes, "scopes cannot be empty");
			Assert.notNull(aTokenMinutes, "aTokenMinutes cannot be null");
			Assert.notNull(rTokenMinutes, "rTokenMinutes cannot be null");
		}

		Consumer<Set<AuthorizationGrantType>> createGrantTypes() {

			final Set<AuthorizationGrantType> source = grantTypes.stream().map(s -> switch (s) {
				case "password" -> AuthorizationGrantType.PASSWORD;
				case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
				case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
				case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
				case "jwt-bearer" -> AuthorizationGrantType.JWT_BEARER;
				case "device_code" -> AuthorizationGrantType.DEVICE_CODE;
				case "token-exchange" -> AuthorizationGrantType.TOKEN_EXCHANGE;
				default -> new AuthorizationGrantType(s);
			}).collect(Collectors.toUnmodifiableSet());

			return ss -> ss.addAll(source);
		}

		Consumer<Set<ClientAuthenticationMethod>> createMethods() {

			final Set<ClientAuthenticationMethod> source = methods.stream().map(s -> switch (s) {
				case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
				case "none" -> ClientAuthenticationMethod.NONE;
				case "tls_client_auth" -> ClientAuthenticationMethod.TLS_CLIENT_AUTH;
				case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
				case "client_secret_jwt" -> ClientAuthenticationMethod.CLIENT_SECRET_JWT;
				case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
				case "self_signed_tls_client_auth" -> ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
				default -> new ClientAuthenticationMethod(s);
			}).collect(Collectors.toUnmodifiableSet());

			return ss -> ss.addAll(source);
		}

		TokenSettings createTokenSettings() {
			return TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(aTokenMinutes)).refreshTokenTimeToLive(Duration.ofMinutes(rTokenMinutes)).build();
		}
	}

	public static List<RegisteredClient> createRegisteredClientFromFile(final Jackson2ObjectMapperBuilder builder) throws IOException {

		final String source = Files.readString(ResourceUtils.getFile(REGISTERED_CLIENT_FILE_PATH).toPath(), StandardCharsets.UTF_8);
		final List<ClientInfo> ci = builder.build().setPropertyNamingStrategy(PropertyNamingStrategies.LOWER_CAMEL_CASE).readerForListOf(ClientInfo.class).readValue(source);

		ci.forEach(ClientInfo::executeAsserts);

		return ci.stream().map(ClientSetting::createClientFrom).toList();
	}

	private static RegisteredClient createClientFrom(final ClientInfo source) {

		final RegisteredClient.Builder builder = RegisteredClient.withId(source.id()).clientId(source.client()).clientSecret(source.secret())
				.clientName(source.client()).authorizationGrantTypes(source.createGrantTypes()).clientAuthenticationMethods(source.createMethods())
				.scopes(s -> s.addAll(source.scopes())).tokenSettings(source.createTokenSettings());

		return StringUtils.hasText(source.redirectUri()) ? builder.redirectUri(source.redirectUri()).build() : builder.build();
	}
}
