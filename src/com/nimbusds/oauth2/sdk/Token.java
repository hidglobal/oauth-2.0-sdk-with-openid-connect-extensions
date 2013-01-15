package com.nimbusds.openid.connect.sdk.messages;


import org.apache.commons.lang3.RandomStringUtils;

import com.nimbusds.openid.connect.sdk.util.StringUtils;


/**
 * The base class for OAuth 2.0 access and refresh tokens.
 * 
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 1.5.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-12)
 */
public abstract class Token {


	/**
	 * The access token value.
	 */
	private final String value;


	/**
	 * Creates a new token with the specified value.
	 *
	 * @param value The token value. Must not be {@code null} or empty 
	 *              string.
	 */
	protected Token(final String value) {

		if (StringUtils.isUndefined(value))
			throw new IllegalArgumentException("The access token value must not be null or empty string");
			
		this.value = value;
	}


	/**
	 * Creates a new token with a randomly generated value of the specified
	 * length. The value will be made up of mixed-case alphanumeric ASCII 
	 * characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	protected Token(final int length) {
	
		this(RandomStringUtils.randomAlphanumeric(length));
	}
	
	
	/**
	 * Creates a new token with a randomly generated value. The value will 
	 * be made up of 32 mixed-case alphanumeric ASCII characters.
	 */
	protected Token() {
	
		this(32);
	}


	/**
	 * Gets the value of this access token.
	 *
	 * @return The value.
	 */
	public String getValue() {
	
		return value;
	}


	/**
	 * Gets the string representation of this token.
	 *
	 * <p> See {@link #getValue}.
	 *
	 * @return The token value.
	 */
	@Override
	public String toString() {
	
		return value;
	}


	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	@Override
	public int hashCode() {
	
		return value.hashCode();
	}
}
