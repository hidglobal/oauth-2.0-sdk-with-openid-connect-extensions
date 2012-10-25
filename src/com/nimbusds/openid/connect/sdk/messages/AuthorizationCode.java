package com.nimbusds.openid.connect.sdk.messages;



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
 * @version $version$ (2012-10-21)
 */
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
	
		if (value == null || value.trim().isEmpty())
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
}
