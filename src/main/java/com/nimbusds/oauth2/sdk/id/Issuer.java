package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * Issuer identifier. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class Issuer extends Identifier {


	/**
	 * Creates a new issuer identifier with the specified value.
	 *
	 * @param value The issuer identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public Issuer(final String value) {

		super(value);
	}


	/**
	 * Creates a new issuer identifier with a randomly generated value of 
	 * the specified length. The value will be made up of mixed-case 
	 * alphanumeric ASCII characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public Issuer(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new issuer identifier with a randomly generated value. The
	 * value will be made up of 32 mixed-case alphanumeric ASCII 
	 * characters.
	 */
	public Issuer() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof Issuer && 
		       this.toString().equals(object.toString());
	}
}