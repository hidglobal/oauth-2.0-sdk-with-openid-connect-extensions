package com.nimbusds.openid.connect.sdk;


import com.nimbusds.openid.connect.sdk.messages.ErrorCode;


/**
 * General OpenID Connect exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-15)
 */
public class OpenIDConnectException extends Exception {


	/**
	 * The associated OpenID Connect error code.
	 */
	private final ErrorCode errorCode;


	/**
	 * Creates a new OpenID Connect exception.
	 *
	 * @param message The exception message.
	 */
	public OpenIDConnectException(final String message) {
	
		this(message, null, null);
	}
	
	
	/**
	 * Creates a new OpenID Connect exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public OpenIDConnectException(final String message, 
		                      final Throwable cause) {
	
		this(message, null, cause);
	}


	/**
	 * Creates a new OpenID Connect exception.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 */
	public OpenIDConnectException(final String message, 
		                      final ErrorCode errorCode) {
	
		this(message, errorCode, null);
	}


	/**
	 * Creates a new OpenID Connect exception.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 * @param cause     The exception cause.
	 */
	public OpenIDConnectException(final String message, 
		                      final ErrorCode errorCode,
		                      final Throwable cause) {
	
		super(message, cause);

		this.errorCode = errorCode;
	}


	/**
	 * Gets the associated OpenID Connect error code.
	 *
	 * @return The associated OpenID Connect error code, {@code null} if
	 *         not specified.
	 */
	public ErrorCode getErrorCode() {

		return errorCode;
	}
}
