package io.doe.common;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see Constants
 * @since 2024-07-08
 */

public final class Constants {

	public static final String BASE_PACKAGE = "io.doe";
	public static final String UNSUPPORTED_OPERATION_MESSAGE = "cannot create instance of this class";

	private Constants() {
		throw new UnsupportedOperationException(UNSUPPORTED_OPERATION_MESSAGE);
	}
}
