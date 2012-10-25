package com.nimbusds.openid.connect.sdk.messages;


import org.apache.commons.lang3.RandomStringUtils;

import com.nimbusds.openid.connect.sdk.util.StringUtils;


/**
 * Nonce. This is a random, unique string value to associate a user-session with
 * an ID Token and to mitigate replay attacks. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1 and 2.1.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-10)
 */
public final class Nonce {


	/**
	 * The nonce value.
	 */
	private final String value;
	
	
	/**
	 * Creates a new nonce.
	 *
	 * @param value The nonce value, must not be {@code null} or empty 
	 *              string.
	 */
	public Nonce(final String value) {
	
		if (StringUtils.isUndefined(value))
			throw new IllegalArgumentException("Null or empty nonce value");
		
		this.value = value;
	}
	
	
	/**
	 * Returns the string representation of this nonce.
	 *
	 * @return The string representation.
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
	
		return object instanceof Nonce && this.toString().equals(object.toString());
	}
	
	
	
	/**
	 * Generates a random nonce with the specified number of alphanumeric
	 * characters.
	 *
	 * @param count The number of characters.
	 *
	 * @return A new random nonce.
	 */
	public static Nonce generate(final int count) {
	
		return new Nonce(RandomStringUtils.randomAlphanumeric(count));
	}
	
	
	/**
	 * Generates a random nonce with 8 alphanumeric characters.
	 *
	 * @return A new random nonce.
	 */
	public static Nonce generate() {
	
		return new Nonce(RandomStringUtils.randomAlphanumeric(8));
	}
	
	
	/**
	 * Parses a nonce from the specified string.
	 *
	 * @param s The string to parse, {@code null} or empty if no nonce is
	 *          specified.
	 *
	 * @return The nonce, {@code null} if the parsed string was {@code null}
	 *         or empty.
	 */
	public static Nonce parse(final String s) {
	
		if (StringUtils.isUndefined(s))
			return null;
		
		return new Nonce(s);
	}
}
