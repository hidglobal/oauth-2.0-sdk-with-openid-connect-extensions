package com.nimbusds.openid.connect;


/**
 * Serialization exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-22)
 */
public class SerializeException extends OpenIDConnectException {


	/**
	 * Creates a new serialisation exception.
	 *
	 * @param message The exception message.
	 */
	public SerializeException(final String message) {
	
		super(message);
	}
	
	
	/**
	 * Creates a new serialisation exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public SerializeException(final String message, final Throwable cause) {
	
		super(message, cause);
	}
}
