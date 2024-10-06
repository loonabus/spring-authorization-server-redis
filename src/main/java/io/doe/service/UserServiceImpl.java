package io.doe.service;

import io.doe.domain.User;
import io.doe.persistence.UserInfoRepo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see UserServiceImpl
 * @since 2024-07-08
 */

@Slf4j
@Service
public class UserServiceImpl implements UserService, BaseService {

	private final UserInfoRepo repo;
	private final MessageSourceAccessor accessor;

	@Autowired
	public UserServiceImpl(final UserInfoRepo repo, final MessageSourceAccessor accessor) {
		this.repo = repo; this.accessor = accessor;
	}

	@Override
	public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
		return retrieveUser(username);
	}

	@Override
	public User retrieveUser(final String userId) throws UsernameNotFoundException {
		return repo.findById(userId).map(u -> new User(u.getUserId(), u.getUserPw(), u.getAdminYn())).orElseThrow(() -> new UsernameNotFoundException(retrieveMessageFrom("user.not-found")));
	}

	@Override
	public MessageSourceAccessor retrieveAccessor() {
		return accessor;
	}
}
