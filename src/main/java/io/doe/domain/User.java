package io.doe.domain;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.io.Serial;
import java.util.Collection;
import java.util.List;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see User
 * @since 2024-07-08
 */

@EqualsAndHashCode(of={"username"})
public final class User implements UserDetails {

	@Serial
	private static final long serialVersionUID = 1L;

	@Getter private final String username;
	@Getter private final String password;
	private final boolean adminYn;

	public User(final String username, final String password, final String adminYn) {

		Assert.hasText(username, "username should have text");
		Assert.hasText(password, "password should have text");
		Assert.hasText(adminYn, "adminYn should have text");

		this.username = username; this.password = password; this.adminYn = "Y".equalsIgnoreCase(adminYn);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(adminYn ? new SimpleGrantedAuthority("ADMIN") : new SimpleGrantedAuthority("USER"));
	}
}
