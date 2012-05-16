package com.nimbusds.openid.connect.messages;


import org.apache.commons.lang3.RandomStringUtils;


/**
 * Opaque value used to maintain state between a request and a callback. Also
 * serves as a protection against XSRF attacks.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-09)
 */
public class State {


	/**
	 * The state string.
	 */
	private String value;
	
	
	/**
	 * Creates a new state value.
	 *
	 * @param value The state value, must not be {@code null} or empty 
	 *              string.
	 */
	public State(final String value) {
	
		if (value == null)
			throw new NullPointerException("The state value must not be null");
			
		if (value.trim().isEmpty())
			throw new IllegalArgumentException("The state value must not be empty");
		
		this.value = value;
	}
	
	
	/**
	 * Returns the string representation of this state value.
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
	
		return object instanceof State && this.toString().equals(object.toString());
	}
	
	
	
	/**
	 * Generates a random state value with the specified number of 
	 * alphanumeric characters.
	 *
	 * @param count The number of characters.
	 *
	 * @return A new random state value.
	 */
	public static State generate(final int count) {
	
		return new State(RandomStringUtils.randomAlphanumeric(count));
	}
	
	
	/**
	 * Generates a random state value with 8 alphanumeric characters.
	 *
	 * @return A new random state value.
	 */
	public static State generate() {
	
		return new State(RandomStringUtils.randomAlphanumeric(8));
	}
}
