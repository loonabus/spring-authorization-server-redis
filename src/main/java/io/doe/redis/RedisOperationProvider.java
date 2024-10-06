package io.doe.redis;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see RedisOperationProvider
 * @since 2024-08-02
 */
public interface RedisOperationProvider {

	String BASE_KEY_PREFIX = "authorization-server:";
	String RC_KEY_PREFIX = BASE_KEY_PREFIX + "rc:";
	String AUTH_KEY_PREFIX = BASE_KEY_PREFIX + "auth:";

	@Nullable
	@SuppressWarnings("unchecked")
	default <T> T getValue(final String k) { return (T)getRedisTemplate().opsForValue().get(k); }

	default Long count(final List<Object> source) {

		final Predicate<Object> predicate = o -> {
			if (Objects.isNull(o)) { return false; }

			return switch (o) {
				case String  s -> Objects.equals("OK", s);
				case Boolean b -> b;
				case Number  n -> n.intValue() > 0;
				default -> !(o instanceof Throwable);
			};
		};

		return source.stream().filter(predicate).count();
	}

	RedisTemplate<String, Object> getRedisTemplate();
}
