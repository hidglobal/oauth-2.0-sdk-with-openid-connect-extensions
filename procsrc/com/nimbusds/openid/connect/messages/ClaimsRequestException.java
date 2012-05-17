package com.nimbusds.openid.connect.messages;


/**
 * Claims request exception.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-09)
 */
public class ClaimsRequestException extends Exception {


	/**
	 * Creates a new claims request exception with the specified message.
	 *
	 * @param message The message.
	 */
	public ClaimsRequestException (final String message) {
	
		super(message);
	}
}
