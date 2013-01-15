package com.nimbusds.oauth2.sdk;


import net.jcip.annotations.Immutable;


/**
 * Subject identifier. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
@Immutable
public final class Subject extends Identifier {


	/**
	 * Creates a new subject identifier with the specified value.
	 *
	 * @param value The subject identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public Subject(final String value) {

		super(value);
	}


	/**
	 * Creates a new subject identifier with a randomly generated value of 
	 * the specified length. The value will be made up of mixed-case 
	 * alphanumeric ASCII characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public Subject(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new subject identifier with a randomly generated value. 
	 * The value will be made up of 32 mixed-case alphanumeric ASCII 
	 * characters.
	 */
	public Subject() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof Subject && 
		       this.toString().equals(object.toString());
	}
}