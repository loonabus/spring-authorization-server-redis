package io.doe.config.oauth2.converter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see AbstractOAuth2AuthConverter
 * @since 2024-07-20
 */

public abstract class AbstractOAuth2AuthConverter<T extends Authentication> implements AuthenticationConverter {

	private static final Set<String> EXCLUSION_PARAMETERS;

	static {
		EXCLUSION_PARAMETERS = Stream.concat(CustomGrantTypes.toSet().stream(), Set.of(OAuth2ParameterNames.GRANT_TYPE, OAuth2ParameterNames.CLIENT_ID).stream()).collect(Collectors.toSet());
	}

	private MultiValueMap<String, String> getParametersFrom(final HttpServletRequest request) {

		final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

		request.getParameterMap().forEach((k, vs) -> {
			if (Objects.nonNull(vs)) {
				for (final String v : vs) { parameters.add(k, v); }
			}
		});

		return parameters;
	}

	@Nullable
	@Override
	public Authentication convert(final HttpServletRequest request) {

		final MultiValueMap<String, String> parameters = getParametersFrom(request);

		if (!retrieveSupportedGrantType().getValue().equals(parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))) { return null; }

		final String uid = retrieveUserIdentifier(parameters);
		final Map<String, Object> misc = new HashMap<>();
		parameters.forEach((k, v) -> {
			if (!EXCLUSION_PARAMETERS.contains(k)) {
				misc.put(k, v.size() == 1 ? v.getFirst() : v.toArray(new String[0]));
			}
		});

		final Set<String> scope = CollectionUtils.isEmpty(parameters.get(OAuth2ParameterNames.SCOPE)) ? Set.of() :
				parameters.get(OAuth2ParameterNames.SCOPE).stream().filter(StringUtils::hasText).map(String::strip).collect(Collectors.toSet());

		return createAuthentication(uid, misc, scope);
	}

	private String retrieveUserIdentifier(final MultiValueMap<String, String> parameters) {

		final String name = retrieveSupportedGrantType().getValue();
		final List<String> uid = parameters.get(name);
		if (Objects.isNull(uid) || (uid.size() != 1 && !StringUtils.hasText(uid.getFirst()))) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 custom parameter: " + name, ""));
		}

		return checkExtraAndReturnIfApplicable(uid);
	}

	abstract AuthorizationGrantType retrieveSupportedGrantType();
	abstract String checkExtraAndReturnIfApplicable(final List<String> uid);
	abstract T createAuthentication(final String uid, final Map<String, Object> misc, final Set<String> scope);

	public enum CustomGrantTypes {

		UIP;

		public static AuthorizationGrantType from(final CustomGrantTypes type) {
			return new AuthorizationGrantType(type.name().toLowerCase());
		}

		public static Set<String> toSet() {
			return Arrays.stream(values()).map(e -> e.name().toLowerCase()).collect(Collectors.toSet());
		}
	}
}
