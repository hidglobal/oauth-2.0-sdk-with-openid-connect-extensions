package com.nimbusds.openid.connect.sdk;


import com.nimbusds.openid.connect.sdk.messages.ErrorCode;


/**
 * Serialization exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-27)
 */
public class SerializeException extends OpenIDConnectException {


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
