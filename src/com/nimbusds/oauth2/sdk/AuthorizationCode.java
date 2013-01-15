package com.nimbusds.openid.connect.sdk.messages;


import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.RandomStringUtils;

import com.nimbusds.openid.connect.sdk.util.StringUtils;


/**
 * OAuth 2.0 authorisation code. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-21)
 */
@Immutable
public final class AuthorizationCode {


	/**
	 * The code value.
	 */
	private final String value;
	
	
	/**
	 * Creates a new authorisation code.
	 *
	 * @param value The code value. Must not be {@code null} or empty 
	 *              string.
	 *
	 * @throws IllegalArgumentException If the code value is {@code null} or
	 *                                  empty string.
	 */
	public AuthorizationCode(final String value) {
	
		if (StringUtils.isUndefined(value))
			throw new IllegalArgumentException("The authorization code value must not be null or empty string");
		
		this.value = value;
	}
	
	
	/**
	 * Gets the value of this authorisation code.
	 *
	 * @return The value.
	 */
	public String getValue() {
	
		return value;
	}
	
	
	/**
	 * Gets the string representation of this authorisation code.
	 *
	 * <p> See {@link #getValue}.
	 *
	 * @return The authorisation code value.
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
	
	
	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same value, otherwise
	 *         {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AuthorizationCode && this.toString().equals(object.toString());
	}


	/**
	 * Generates a random authorisation code with the specified number of 
	 * alphanumeric characters.
	 *
	 * @param count The number of characters.
	 *
	 * @return A new random authorisation code.
	 */
	public static AuthorizationCode generate(final int count) {
	
		return new AuthorizationCode(RandomStringUtils.randomAlphanumeric(count));
	}
	
	
	/**
	 * Generates a random authorisation code with 8 alphanumeric 
	 * characters.
	 *
	 * @return A new random authorisation code.
	 */
	public static AuthorizationCode generate() {
	
		return generate(8);
	}
}
