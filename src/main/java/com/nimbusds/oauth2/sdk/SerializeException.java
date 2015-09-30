package com.nimbusds.oauth2.sdk;


/**
 * Serialization exception (unchecked).
 */
public class SerializeException extends RuntimeException {


	/**
	 * Creates a new serialisation exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public SerializeException(final String message) {
	
		this(message, null);
	}
	
	
	/**
	 * Creates a new serialisation exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public SerializeException(final String message, final Throwable cause) {
	
		super(message, cause);
	}
}
