package io.doe.service;

import io.doe.common.Constants;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.lang.Nullable;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see BaseService
 * @since 2024-07-08
 */

public interface BaseService {

	default String retrieveMessageFrom(final String k, @Nullable final Object... arr) {
		return retrieveAccessor().getMessage(Constants.BASE_PACKAGE + ".service." + k, arr, LocaleContextHolder.getLocale());
	}

	MessageSourceAccessor retrieveAccessor();
}
