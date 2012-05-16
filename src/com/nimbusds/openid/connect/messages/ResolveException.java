package com.nimbusds.openid.connect.messages;


import com.nimbusds.openid.connect.OpenIDConnectException;


/**
 * Resolve exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-23)
 */
public class ResolveException extends OpenIDConnectException {


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message The exception message.
	 */
	public ResolveException(final String message) {
	
		super(message);
	}
	
	
	/**
	 * Creates a new resolve exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public ResolveException(final String message, final Throwable cause) {
	
		super(message, cause);
	}
}
