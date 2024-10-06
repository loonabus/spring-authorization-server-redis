package io.doe.config.oauth2.auth;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.io.Serial;
import java.util.Map;
import java.util.Set;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see OAuthCustomAuthToken
 * @since 2024-07-21
 */

@Getter
@EqualsAndHashCode(callSuper=true, of="code")
public class OAuthCustomAuthToken extends OAuth2AuthorizationGrantAuthenticationToken {

	@Serial private static final long serialVersionUID = 1L;

	private final String code;
	private final Set<String> scope;

	public OAuthCustomAuthToken(final String code, final Set<String> scope, AuthorizationGrantType type, final Authentication authentication, @Nullable Map<String, Object> misc) {
		super(type, authentication, misc); this.code = code; this.scope = scope;
	}
}
