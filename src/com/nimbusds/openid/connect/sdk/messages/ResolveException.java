package com.nimbusds.openid.connect.sdk.messages;


import com.nimbusds.openid.connect.sdk.OpenIDConnectException;


/**
 * Resolve exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-15)
 */
public class ResolveException extends OpenIDConnectException {


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message The exception message.
	 */
	public ResolveException(final String message) {
	
		this(message, null, null);
	}
	
	
	/**
	 * Creates a new resolve exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public ResolveException(final String message, final Throwable cause) {
	
		this(message, null, cause);
	}


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 */
	public ResolveException(final String message, 
		                final ErrorCode errorCode) {
	
		this(message, errorCode, null);
	}


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 * @param cause     The exception cause.
	 */
	public ResolveException(final String message, 
		                final ErrorCode errorCode,
		                final Throwable cause) {
	
		super(message, errorCode, cause);
	}
}
