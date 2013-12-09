package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * Subject identifier. This class is immutable.
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
	 * the specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public Subject(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new subject identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public Subject() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Subject &&
		       this.toString().equals(object.toString());
	}
}