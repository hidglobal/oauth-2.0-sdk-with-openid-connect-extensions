package com.nimbusds.openid.connect;


/**
 * Parse exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-22)
 */
public class ParseException extends OpenIDConnectException {


	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message.
	 */
	public ParseException(final String message) {
	
		super(message);
	}
	
	
	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public ParseException(final String message, final Throwable cause) {
	
		super(message, cause);
	}
}
