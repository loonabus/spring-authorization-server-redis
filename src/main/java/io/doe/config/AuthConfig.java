package io.doe.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.doe.config.oauth2.converter.OAuth2UipAuthConverter;
import io.doe.config.oauth2.provider.OAuth2ExtendedRefreshTokenAuthenticationProvider;
import io.doe.config.oauth2.provider.OAuth2UipAuthTokenProvider;
import io.doe.domain.BaseRes;
import io.doe.redis.RedisClientRepositories;
import io.doe.redis.RedisOAuth2AuthorizationService;
import io.doe.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ResourceUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see AuthConfig
 * @since 2024-07-08
 */

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(BaseProperties.Auth.class)
public class AuthConfig {

	private final BaseProperties.Auth props;

	@Autowired
	public AuthConfig(final BaseProperties.Auth props) { this.props = props; }

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	public SecurityFilterChain authorizationFilterChain(final HttpSecurity http, final PasswordEncoder encoder, final RegisteredClientRepository repo,
			final OAuth2AuthorizationService oAuth2, final OAuth2TokenGenerator<? extends OAuth2Token> generator, final UserService service, final Jackson2ObjectMapperBuilder builder) throws Exception {

		final OAuth2AuthorizationServerConfigurer configurer = new OAuth2AuthorizationServerConfigurer();
		final RequestMatcher matcher = configurer.getEndpointsMatcher();

		configurer.tokenEndpoint(ec -> {
			ec.accessTokenResponseHandler(new AccessTokenAuthenticationSuccessHandler());
			ec.accessTokenRequestConverters(cc -> cc.addAll(0, List.of(new OAuth2UipAuthConverter())));
			ec.authenticationProviders(pc -> pc.addAll(0, List.of(new OAuth2UipAuthTokenProvider(encoder, repo, oAuth2, generator, service), new OAuth2ExtendedRefreshTokenAuthenticationProvider(oAuth2, generator))));
		});

		http.cors(Customizer.withDefaults());
		http.csrf(cc -> cc.ignoringRequestMatchers(matcher)).securityMatcher(matcher).authorizeHttpRequests(rc -> rc.anyRequest().authenticated()).with(configurer, sc -> sc.oidc(Customizer.withDefaults()));

		http.oauth2ResourceServer(rsc -> rsc.jwt(Customizer.withDefaults()));
		http.exceptionHandling(createExceptionConfigurerCustomizerWithFormLogin(builder.build()));

		return http.build();
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 2)
	public SecurityFilterChain standardFilterChain(final HttpSecurity http, final Jackson2ObjectMapperBuilder builder) throws Exception {

		http.cors(Customizer.withDefaults()).formLogin(Customizer.withDefaults());
		http.csrf(AbstractHttpConfigurer::disable).httpBasic(AbstractHttpConfigurer::disable);
		http.authorizeHttpRequests(rc -> rc.requestMatchers("/error").permitAll().anyRequest().authenticated());
		http.exceptionHandling(createExceptionConfigurerCustomizer(builder.build()));

		return http.build();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() { return AuthorizationServerSettings.builder().build(); }

	@Bean
	public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

	@Bean
	@Conditional(EmbedMode.class)
	public RegisteredClientRepository registeredClientRepo(final Jackson2ObjectMapperBuilder builder) throws IOException {
		return new InMemoryRegisteredClientRepository(ClientSetting.createRegisteredClientFromFile(builder, props.getRcPath()).toArray(new RegisteredClient[0]));
	}

	@Bean
	@Conditional(EmbedMode.class)
	public OAuth2AuthorizationService oAuth2AuthorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	@Conditional(RedisMode.class)
	public RegisteredClientRepository redisRegisteredClientRepo(
			final Jackson2ObjectMapperBuilder builder, final RedisTemplate<String, Object> redisTemplate) throws IOException {
		return new RedisClientRepositories(ClientSetting.createRegisteredClientFromFile(builder, props.getRcPath()), redisTemplate);
	}

	@Bean
	@Conditional(RedisMode.class)
	public OAuth2AuthorizationService redisOAuth2AuthorizationService(final RedisTemplate<String, Object> redisTemplate) {
		return new RedisOAuth2AuthorizationService(redisTemplate);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		final KeyFactory factory = KeyFactory.getInstance("RSA");
		final byte[] prValue = Base64.decodeBase64(Files.readAllBytes(ResourceUtils.getFile(props.getRsaPath()).toPath()));
		final byte[] puValue = Base64.decodeBase64(Files.readAllBytes(ResourceUtils.getFile(props.getRsaPath() + ".pub").toPath()));

		final RSAKey k = new RSAKey.Builder((RSAPublicKey)factory.generatePublic(new X509EncodedKeySpec(puValue)))
				.privateKey((RSAPrivateKey)factory.generatePrivate(new PKCS8EncodedKeySpec(prValue))).keyID(UUID.randomUUID().toString()).build();

		return new ImmutableJWKSet<>(new JWKSet(k));
	}

	@Bean
	public JwtDecoder jwtDecoder(final JWKSource<SecurityContext> source) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(source);
	}

	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> createTokenGenerator(final JWKSource<SecurityContext> source) {

		final OAuth2TokenCustomizers customizers = new OAuth2TokenCustomizers();

		final JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(source));
		jwtGenerator.setJwtCustomizer(customizers.retrieveJwtTokenContextCustomizer());

		final OAuth2AccessTokenGenerator tokenGenerator = new OAuth2AccessTokenGenerator();
		tokenGenerator.setAccessTokenCustomizer(customizers.retrieveOAuth2TokenContextCustomizer());

		return new DelegatingOAuth2TokenGenerator(jwtGenerator, tokenGenerator, new OAuth2RefreshTokenGenerator());
	}

	@Slf4j
	static class AccessTokenAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

		private final Consumer<OAuth2AccessTokenAuthenticationContext> consumer;
		private final HttpMessageConverter<OAuth2AccessTokenResponse> converter;

		public AccessTokenAuthenticationSuccessHandler() {
			this.consumer = c -> {};
			this.converter = new OAuth2AccessTokenResponseHttpMessageConverter();
		}

		@Override
		public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication auth) throws IOException {

			if (!(auth instanceof OAuth2AccessTokenAuthenticationToken aTokenAuth)) {
				log.error("{} must be of type {} but was {}", Authentication.class.getSimpleName(), OAuth2AccessTokenAuthenticationToken.class.getName(), auth.getClass().getName());
				throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Unable to process the access token response.", null));
			}

			final OAuth2AccessToken aToken = aTokenAuth.getAccessToken();
			final OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse.withToken(aToken.getTokenValue()).tokenType(aToken.getTokenType()).scopes(aToken.getScopes());

			if (Objects.nonNull(aToken.getIssuedAt()) && Objects.nonNull(aToken.getExpiresAt())) {
				builder.expiresIn(ChronoUnit.SECONDS.between(aToken.getIssuedAt(), aToken.getExpiresAt()));
			}

			if (Objects.nonNull(aTokenAuth.getRefreshToken())) { builder.refreshToken(aTokenAuth.getRefreshToken().getTokenValue()); }
			builder.additionalParameters(aTokenAuth.getAdditionalParameters());

			consumer.accept(OAuth2AccessTokenAuthenticationContext.with(aTokenAuth).accessTokenResponse(builder).build());
			converter.write(builder.build(), null, new ServletServerHttpResponse(response));
		}
	}

	static class OAuth2TokenCustomizers {

		private static final Set<ClientAuthenticationMethod> POSSIBLE_METHOD =
				Set.of(ClientAuthenticationMethod.TLS_CLIENT_AUTH, ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);

		OAuth2TokenCustomizer<JwtEncodingContext> retrieveJwtTokenContextCustomizer() {
			return ec -> ec.getClaims().claims(c -> customize(ec, c));
		}

		OAuth2TokenCustomizer<OAuth2TokenClaimsContext> retrieveOAuth2TokenContextCustomizer() {
			return cc -> cc.getClaims().claims(c -> customize(cc, c));
		}

		private void customize(final OAuth2TokenContext context, final Map<String, Object> claim) {

			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				putCnfThumbprintClaimIfApplicable(context, claim);
			}

			if (context.getPrincipal() instanceof OAuth2TokenExchangeCompositeAuthenticationToken auth) {
				Map<String, Object> current = claim;

				for (final OAuth2TokenExchangeActor actor : auth.getActors()) {
					Map<String, Object> c = new LinkedHashMap<>();

					c.put(OAuth2TokenClaimNames.ISS, actor.getClaims().get(OAuth2TokenClaimNames.ISS));
					c.put(OAuth2TokenClaimNames.SUB, actor.getClaims().get(OAuth2TokenClaimNames.SUB));

					current.put("act", Collections.unmodifiableMap(c));
					current = c;
				}
			}
		}

		private String computeSHA256Thumbprint(X509Certificate x509Certificate) throws NoSuchAlgorithmException, CertificateEncodingException {
			return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(x509Certificate.getEncoded()));
		}

		private void putCnfThumbprintClaimIfApplicable(final OAuth2TokenContext context, Map<String, Object> claim) {

			if (Objects.nonNull(context.getAuthorizationGrant())
					&& context.getAuthorizationGrant().getPrincipal() instanceof OAuth2ClientAuthenticationToken authToken
					&& POSSIBLE_METHOD.contains(authToken.getClientAuthenticationMethod())
					&& context.getRegisteredClient().getTokenSettings().isX509CertificateBoundAccessTokens()) {

				final X509Certificate[] certificates = (X509Certificate[])authToken.getCredentials();
				try {
					claim.put("cnf", Map.of("x5t#S256", computeSHA256Thumbprint(Objects.requireNonNull(certificates)[0])));
				} catch (final Exception e) {
					throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Failed to compute SHA-256 Thumbprint for client X509Certificate.", null), e);
				}
			}
		}
	}

	interface ForbiddenResponseSender {

		default void sendJsonErrorResponse(final HttpServletResponse response) throws IOException {

			response.setStatus(HttpStatus.FORBIDDEN.value());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setCharacterEncoding(StandardCharsets.UTF_8.name());

			try {
				response.getWriter().write(retrieveObjectMapper().writeValueAsString(BaseRes.from("Access Denied")));
			} catch (final JsonProcessingException e) {
				retrieveLogger().trace("", e); response.getWriter().write("Access Denied");
			}
		}

		Logger retrieveLogger();
		ObjectMapper retrieveObjectMapper();
	}

	@Slf4j
	static class ForbiddenAccessDeniedHandler implements AccessDeniedHandler, ForbiddenResponseSender {

		private final ObjectMapper mapper;

		ForbiddenAccessDeniedHandler(final ObjectMapper mapper) {
			this.mapper = mapper;
		}

		@Override
		public void handle(final HttpServletRequest request, final HttpServletResponse response, final AccessDeniedException e) throws IOException {

			log.debug("access denied", e);
			if (response.isCommitted()) { log.trace("Did not write to response since already committed"); return; }
			sendJsonErrorResponse(response);
		}

		@Override public Logger retrieveLogger() { return log; }
		@Override public ObjectMapper retrieveObjectMapper() { return mapper; }
	}

	@Slf4j
	static class ForbiddenAuthenticationEntryPoint implements AuthenticationEntryPoint, ForbiddenResponseSender {

		private final ObjectMapper mapper;

		ForbiddenAuthenticationEntryPoint(final ObjectMapper mapper) {
			this.mapper = mapper;
		}

		@Override
		public void commence(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException e) throws IOException {
			log.debug("pre-authenticated entry point called. rejecting access", e);
			sendJsonErrorResponse(response);
		}

		@Override public Logger retrieveLogger() { return log; }
		@Override public ObjectMapper retrieveObjectMapper() { return mapper; }
	}

	private Customizer<ExceptionHandlingConfigurer<HttpSecurity>> createExceptionConfigurerCustomizer(final ObjectMapper mapper) {

		return c -> {
			final RequestMatcher rm = new MediaTypeRequestMatcher(MediaType.ALL, MediaType.APPLICATION_JSON, MediaType.TEXT_HTML);

			c.defaultAccessDeniedHandlerFor(new ForbiddenAccessDeniedHandler(mapper), rm);
			c.defaultAuthenticationEntryPointFor(new ForbiddenAuthenticationEntryPoint(mapper), rm);
		};
	}

	private Customizer<ExceptionHandlingConfigurer<HttpSecurity>> createExceptionConfigurerCustomizerWithFormLogin(final ObjectMapper mapper) {

		return c -> {
			c.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML));
			c.defaultAccessDeniedHandlerFor(new ForbiddenAccessDeniedHandler(mapper), new MediaTypeRequestMatcher(MediaType.ALL, MediaType.APPLICATION_JSON));
		};
	}

	enum Env {
		REDIS;
		static boolean runWithRedis(final String[] ps) { return Arrays.stream(ps).anyMatch(p -> Arrays.stream(values()).map(e -> e.name().toLowerCase()).collect(Collectors.toSet()).contains(p.toLowerCase())); }
	}

	static class EmbedMode implements Condition {
		@Override
		public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata meta) { return !Env.runWithRedis(context.getEnvironment().getActiveProfiles()); }
	}

	public static class RedisMode implements Condition {
		@Override
		public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata meta) { return  Env.runWithRedis(context.getEnvironment().getActiveProfiles()); }
	}
}