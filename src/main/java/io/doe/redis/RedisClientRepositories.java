package io.doe.redis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see RedisClientRepositories
 * @since 2024-08-01
 */

@Slf4j
public class RedisClientRepositories implements RegisteredClientRepository, RedisOperationProvider {

	private static final String ID_KEY_PREFIX = RC_KEY_PREFIX + "id:";
	private static final String CLIENT_KEY_PREFIX = RC_KEY_PREFIX + "client:";
	private static final String DUPLICATED_MESSAGE = "registered client must be unique. Found duplicate ";

	private final RedisTemplate<String, Object> redisTemplate;

	public RedisClientRepositories(final List<RegisteredClient> source, final RedisTemplate<String, Object> redisTemplate) {
		this.redisTemplate = redisTemplate; afterPropertiesSet(source);
	}

	@Override
	public void save(final RegisteredClient source) {

		Assert.notNull(source, "registered client cannot be null");

		if (Objects.isNull(getValue(ID_KEY_PREFIX + source.getId()))) {
			checkUniqueness(source);
		}

		putRegisteredClientIntoRedis(List.of(source), true);
	}

	@Override
	public RegisteredClient findById(final String id) {
		return getValue(ID_KEY_PREFIX + id);
	}

	@Override
	public RegisteredClient findByClientId(final String id) {
		return getValue(CLIENT_KEY_PREFIX + id);
	}

	@Override
	public RedisTemplate<String, Object> getRedisTemplate() {
		return redisTemplate;
	}

	public void afterPropertiesSet(final List<RegisteredClient> source) {

		Assert.notEmpty(source, "registered client cannot be null");

		source.forEach(c -> {
			if (Objects.isNull(getValue(ID_KEY_PREFIX + c.getId()))) {
				try {
					checkUniqueness(c);
				} catch (final IllegalArgumentException e) {
					log.info("", e);
				}
			}
		});

		putRegisteredClientIntoRedis(source, false);
	}

	private void putRegisteredClientIntoRedis(final List<RegisteredClient> source, final boolean update) {

		redisTemplate.execute(new SessionCallback<>() {

			@Override @SuppressWarnings("unchecked")
			public Long execute(final RedisOperations ops) throws DataAccessException {

				ops.watch(source.stream().map(s -> ID_KEY_PREFIX + s.getId()).toList());
				ops.multi();

				source.forEach(c -> {
					if (update) {
						ops.opsForValue().multiSet(Map.of(ID_KEY_PREFIX + c.getId(), c, CLIENT_KEY_PREFIX + c.getClientId(), c)); return;
					}
					ops.opsForValue().multiSetIfAbsent(Map.of(ID_KEY_PREFIX + c.getId(), c, CLIENT_KEY_PREFIX + c.getClientId(), c));
				});

				return count(ops.exec());
			}
		});
	}

	private void checkUniqueness(final RegisteredClient source) {

		if (Objects.nonNull(getValue(ID_KEY_PREFIX + source.getId()))) {
			throw new IllegalArgumentException(DUPLICATED_MESSAGE + "id: " + source.getId());
		}

		if (Objects.nonNull(getValue(CLIENT_KEY_PREFIX + source.getClientId()))) {
			throw new IllegalArgumentException(DUPLICATED_MESSAGE + "client: " + source.getClientId());
		}

		final Set<String> ks = Optional.ofNullable(redisTemplate.keys(ID_KEY_PREFIX)).orElse(Set.of());
		Optional.ofNullable(redisTemplate.opsForValue().multiGet(ks)).orElse(List.of()).forEach(v -> {
			final RegisteredClient c = (RegisteredClient) v;
			if (Objects.nonNull(c) && StringUtils.hasText(c.getClientSecret()) && Objects.equals(c.getClientSecret(), source.getClientSecret())) {
				throw new IllegalArgumentException(DUPLICATED_MESSAGE + "client secret: " + source.getClientId());
			}
		});
	}
}
