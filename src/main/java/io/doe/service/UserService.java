package io.doe.service;

import io.doe.domain.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see UserService
 * @since 2024-07-08
 */

public interface UserService extends UserDetailsService {
	User retrieveUser(final String userId) throws UsernameNotFoundException;
}
