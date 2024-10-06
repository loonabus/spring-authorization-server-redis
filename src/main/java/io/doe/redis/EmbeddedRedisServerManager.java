package io.doe.redis;

import io.doe.config.AuthConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Component;
import redis.embedded.RedisServer;

import java.io.IOException;

/**
 * @author <jschoi@smilegate.com>
 * @version 1.0.0
 * @see EmbeddedRedisServerManager
 * @since 2024-10-05
 */

@Slf4j
@Component
@ConditionalOnClass(RedisServer.class)
@Conditional(AuthConfig.RedisMode.class)
public class EmbeddedRedisServerManager implements InitializingBean, DisposableBean {

	private final RedisServer server;

	@Autowired
	public EmbeddedRedisServerManager(final RedisProperties props) throws IOException {
		this.server = RedisServer.newRedisServer().port(props.getPort()).build();
	}

	@Override
	public void destroy() {
		try {
			server.stop();
		} catch (final IOException e) {
			log.info("embedded redis server stop error", e);
		}
	}

	@Override
	public void afterPropertiesSet() throws IOException { server.start(); }
}
