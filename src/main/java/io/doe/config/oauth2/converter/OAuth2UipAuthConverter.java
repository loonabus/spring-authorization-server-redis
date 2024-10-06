package io.doe.config.oauth2.converter;

import io.doe.config.oauth2.auth.OAuth2UipAuthToken;
import org.apache.commons.codec.binary.Base64;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see OAuth2UipAuthConverter
 * @since 2024-07-20
 */
public class OAuth2UipAuthConverter extends AbstractOAuth2AuthConverter<OAuth2UipAuthToken> {

	private static final AuthorizationGrantType GRANT_TYPE = CustomGrantTypes.from(CustomGrantTypes.UIP);

	@Override
	AuthorizationGrantType retrieveSupportedGrantType() { return GRANT_TYPE; }

	@Override
	String checkExtraAndReturnIfApplicable(final List<String> uid) {

		final String source = new String(Base64.decodeBase64(uid.getFirst()));
		if (StringUtils.delimitedListToStringArray(source, ":").length != 2) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "OAuth 2.0 custom parameter: " + GRANT_TYPE.getValue(), ""));
		}

		return source;
	}

	@Override
	OAuth2UipAuthToken createAuthentication(final String uid, final Map<String, Object> misc, final Set<String> scope) {
		final String[] source = StringUtils.delimitedListToStringArray(uid, ":");
		return new OAuth2UipAuthToken(uid, source[0], source[1], scope, SecurityContextHolder.getContext().getAuthentication(), misc);
	}
}
