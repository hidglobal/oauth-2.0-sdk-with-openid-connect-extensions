package com.nimbusds.openid.connect.sdk;


import com.nimbusds.openid.connect.sdk.messages.ErrorCode;


/**
 * Parse exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-15)
 */
public class ParseException extends OpenIDConnectException {


	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message.
	 */
	public ParseException(final String message) {
	
		this(message, null, null);
	}
	
	
	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public ParseException(final String message, final Throwable cause) {
	
		this(message, null, cause);
	}


	/**
	 * Creates a new parse exception.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 */
	public ParseException(final String message, 
		              final ErrorCode errorCode) {
	
		this(message, errorCode, null);
	}


	/**
	 * Creates a new parse exception.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 * @param cause     The exception cause.
	 */
	public ParseException(final String message, 
		              final ErrorCode errorCode,
		              final Throwable cause) {
	
		super(message, errorCode, cause);
	}
}
