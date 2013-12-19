package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;


/**
 * Opaque value used to maintain state between a request and a callback. Also
 * serves as a protection against XSRF attacks, among other uses.
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
	 * byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public State(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new state with a randomly generated 256-bit (32-byte) 
	 * value, Base64URL-encoded.
	 */
	public State() {

		super();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof State &&
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
