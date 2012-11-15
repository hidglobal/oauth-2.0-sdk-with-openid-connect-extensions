package com.nimbusds.openid.connect.sdk;


import com.nimbusds.openid.connect.sdk.messages.ErrorCode;


/**
 * Serialization exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-15)
 */
public class SerializeException extends OpenIDConnectException {


	/**
	 * Creates a new serialisation exception.
	 *
	 * @param message The exception message.
	 */
	public SerializeException(final String message) {
	
		super(message, null, null);
	}
	
	
	/**
	 * Creates a new serialisation exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public SerializeException(final String message, final Throwable cause) {
	
		super(message, null, cause);
	}


	/**
	 * Creates a new serialisation exception.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 */
	public SerializeException(final String message, 
		                  final ErrorCode errorCode) {
	
		this(message, errorCode, null);
	}


	/**
	 * Creates a new serialisation exception.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 * @param cause     The exception cause.
	 */
	public SerializeException(final String message, 
		                  final ErrorCode errorCode,
		                  final Throwable cause) {
	
		super(message, errorCode, cause);
	}
}
