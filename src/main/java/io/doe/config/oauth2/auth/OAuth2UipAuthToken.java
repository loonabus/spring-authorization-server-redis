package io.doe.config.oauth2.auth;

import io.doe.config.oauth2.converter.AbstractOAuth2AuthConverter;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.Serial;
import java.util.Map;
import java.util.Set;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see OAuth2UipAuthToken
 * @since 2024-07-21
 */

@Getter
@EqualsAndHashCode(callSuper=true)
public class OAuth2UipAuthToken extends OAuthCustomAuthToken {

	@Serial private static final long serialVersionUID = 1L;

	private final String id;
	private final String pw;

	public OAuth2UipAuthToken(final String code, final String id, final String pw, final Set<String> scope, final Authentication authentication, @Nullable Map<String, Object> misc) {
		super(code, scope, AbstractOAuth2AuthConverter.CustomGrantTypes.from(AbstractOAuth2AuthConverter.CustomGrantTypes.UIP), authentication, misc); this.id = id; this.pw = pw;
	}
}
