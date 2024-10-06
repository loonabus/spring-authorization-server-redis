package io.doe.config;

import com.github.gavlyukovskiy.boot.jdbc.decorator.DataSourceDecoratorAutoConfiguration;
import com.p6spy.engine.logging.Category;
import com.p6spy.engine.spy.P6SpyOptions;
import com.p6spy.engine.spy.appender.MessageFormattingStrategy;
import jakarta.annotation.PostConstruct;
import org.hibernate.engine.jdbc.internal.FormatStyle;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.format.FormatterRegistry;
import org.springframework.http.HttpMethod;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.Set;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see BaseConfig
 * @since 2024-07-08
 */

@Configuration
public class BaseConfig {

	@Bean
	public WebMvcConfigurer webMvcConfigurer() {

		return new WebMvcConfigurer() {
			@Override
			public void addFormatters(final FormatterRegistry fr) { fr.addConverter(String.class, String.class, String::strip); }

			@Override
			public void addCorsMappings(final CorsRegistry cr) {
				cr.addMapping("/**").allowedOrigins("*").allowedMethods(Arrays.stream(HttpMethod.values()).map(HttpMethod::name).toArray(String[]::new));
			}
		};
	}

	@Bean
	public MessageSourceAccessor messageSourceAccessor(final MessageSource source) {
		return new MessageSourceAccessor(source);
	}

	@Conditional(AuthConfig.RedisMode.class)
	@ConditionalOnClass(RedisOperations.class)
	@AutoConfigureAfter(RedisAutoConfiguration.class)
	public static class RedisTemplateConfig {

		@Bean @Primary
		public RedisTemplate<String, Object> redisJsonTemplate(final RedisConnectionFactory factory) {

			final RedisSerializer<String> ss = new StringRedisSerializer();
			final RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();

			redisTemplate.setConnectionFactory(factory);
			redisTemplate.setKeySerializer(ss); redisTemplate.setHashKeySerializer(ss);

			final ClassLoader classLoader = RedisTemplate.class.getClassLoader();

			if (ClassUtils.isPresent("io.lettuce.core.RedisClient", classLoader)
				&& factory.getClass().isAssignableFrom(LettuceConnectionFactory.class)) {
				((LettuceConnectionFactory)factory).setConvertPipelineAndTxResults(true);
			}
			if (ClassUtils.isPresent("redis.clients.jedis.Jedis", classLoader)
				&& factory.getClass().isAssignableFrom(JedisConnectionFactory.class)) {
				((JedisConnectionFactory)  factory).setConvertPipelineAndTxResults(true);
			}

			return redisTemplate;
		}
	}

	@Configuration
	@AutoConfigureAfter(DataSourceDecoratorAutoConfiguration.class)
	public static class P6SqlLogMessageFormatConfig {

		@PostConstruct
		public void setLogMessageFormat() {
			P6SpyOptions.getActiveInstance().setLogMessageFormat(CustomP6SqlLogFormat.class.getName());
		}
	}

	public static class CustomP6SqlLogFormat implements MessageFormattingStrategy {

		private static final Set<String> DDL_PREFIX = Set.of("create", "alter", "drop", "comment");

		@Override
		public String formatMessage(final int cid, final String now, final long took, final String category, final String prepared, final String q, final String addr) {
			if (!StringUtils.hasText(q)) { return q; }
			return "#" + now + "# | " + took + "ms | " + category + " | connection" + cid + " | " + addr + (Category.STATEMENT.getName().equals(category) ? formatMore(q.strip()) : q.strip());
		}

		private String formatMore(final String source) {
			return (DDL_PREFIX.stream().anyMatch(v -> source.toLowerCase(LocaleContextHolder.getLocale()).startsWith(v)) ? FormatStyle.DDL : FormatStyle.BASIC).getFormatter().format(source);
		}
	}
}
