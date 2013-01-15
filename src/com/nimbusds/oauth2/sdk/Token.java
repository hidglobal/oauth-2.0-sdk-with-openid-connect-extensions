package com.nimbusds.oauth2.sdk;


/**
 * The base abstract class for OAuth 2.0 access and refresh tokens.
 * 
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 1.5.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-01-15)
 */
public abstract class Token extends Identifier {


	/**
	 * Creates a new token with the specified value.
	 *
	 * @param value The token value. Must not be {@code null} or empty 
	 *              string.
	 */
	protected Token(final String value) {

		super(value);
	}


	/**
	 * Creates a new token with a randomly generated value of the specified
	 * length. The value will be made up of mixed-case alphanumeric ASCII 
	 * characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	protected Token(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new token with a randomly generated value. The value will 
	 * be made up of 32 mixed-case alphanumeric ASCII characters.
	 */
	protected Token() {
	
		super();
	}
}
