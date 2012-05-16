package com.nimbusds.openid.connect;


/**
 * General OpenID Connect exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-15)
 */
public class OpenIDConnectException extends Exception {


	/**
	 * Creates a new OpenID Connect exception.
	 *
	 * @param message The exception message.
	 */
	public OpenIDConnectException(final String message) {
	
		super(message);
	}
	
	
	/**
	 * Creates a new OpenID Connect exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public OpenIDConnectException(final String message, final Throwable cause) {
	
		super(message, cause);
	}

}
