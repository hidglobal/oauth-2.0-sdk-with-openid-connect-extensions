package com.nimbusds.oauth2.sdk.id;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;


/**
 * Opaque value used to maintain state between a request and a callback. Also
 * serves as a protection against XSRF attacks, among other uses. This class is
 * immutable.
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class State extends Identifier {


	/**
	 * Creates a new state with the specified value.
	 *
	 * @param value The state value. Must not be {@code null} or empty 
	 *              string.
	 */
	public State(final String value) {
	
		super(value);
	}


	/**
	 * Creates a new state with a randomly generated value of the specified
	 * length. The value will be made up of mixed-case alphanumeric ASCII 
	 * characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public State(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new state with a randomly generated value. The value will
	 * be made up of 32 mixed-case alphanumeric ASCII characters.
	 */
	public State() {

		super();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof State && 
		       this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses a state from the specified string.
	 *
	 * @param s The string to parse, {@code null} or empty if no state is
	 *          specified.
	 *
	 * @return The state, {@code null} if the parsed string was 
	 *         {@code null} or empty.
	 */
	public static State parse(final String s) {
	
		if (StringUtils.isBlank(s))
			return null;
		
		return new State(s);
	}
}
