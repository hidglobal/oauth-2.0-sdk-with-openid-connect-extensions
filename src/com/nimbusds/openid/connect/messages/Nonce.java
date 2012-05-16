package com.nimbusds.openid.connect.messages;


import org.apache.commons.lang3.RandomStringUtils;


/**
 * A random, unique string value to associate a user-session with an ID Token
 * and to mitigate replay attacks.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-09)
 */
public class Nonce {


	/**
	 * The nonce string.
	 */
	private String value;
	
	
	/**
	 * Creates a new nonce.
	 *
	 * @param value The nonce value, must not be {@code null} or empty 
	 *              string.
	 */
	public Nonce(final String value) {
	
		if (value == null)
			throw new NullPointerException("The nonce value must not be null");
			
		if (value.trim().isEmpty())
			throw new IllegalArgumentException("The nonce value must not be empty");
		
		
		this.value = value;
	}
	
	
	/**
	 * Returns the string representation of this nonce.
	 *
	 * @return The string representation.
	 */
	public String toString() {
	
		return value;
	}
	
	
	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
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
}
