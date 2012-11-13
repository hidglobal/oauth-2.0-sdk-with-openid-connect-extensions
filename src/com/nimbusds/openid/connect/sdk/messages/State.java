package com.nimbusds.openid.connect.sdk.messages;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.RandomStringUtils;

import com.nimbusds.openid.connect.sdk.util.StringUtils;


/**
 * Opaque value used to maintain state between a request and a callback. Also
 * serves as a protection against XSRF attacks, among other uses. This class is
 * immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-13)
 */
@Immutable
public final class State {


	/**
	 * The state value.
	 */
	private final String value;
	
	
	/**
	 * Creates a new state.
	 *
	 * @param value The state value, must not be {@code null} or empty 
	 *              string.
	 */
	public State(final String value) {
	
		if (StringUtils.isUndefined(value))
			throw new IllegalArgumentException("Null or empty state value");
		
		this.value = value;
	}
	
	
	/**
	 * Returns the string representation of this state.
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
	
		return object instanceof State && this.toString().equals(object.toString());
	}
	
	
	
	/**
	 * Generates a random state value with the specified number of 
	 * alphanumeric characters.
	 *
	 * @param count The number of characters.
	 *
	 * @return A new random state.
	 */
	public static State generate(final int count) {
	
		return new State(RandomStringUtils.randomAlphanumeric(count));
	}
	
	
	/**
	 * Generates a random state value with 8 alphanumeric characters.
	 *
	 * @return A new random state.
	 */
	public static State generate() {
	
		return new State(RandomStringUtils.randomAlphanumeric(8));
	}
	
	
	/**
	 * Parses a state from the specified string.
	 *
	 * @param s The string to parse, {@code null} or empty if no state is
	 *          specified.
	 *
	 * @return The state, {@code null} if the parsed string was {@code null}
	 *         or empty.
	 */
	public static State parse(final String s) {
	
		if (StringUtils.isUndefined(s))
			return null;
		
		return new State(s);
	}
}
