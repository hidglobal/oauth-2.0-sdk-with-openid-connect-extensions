package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * JSON Web Token (JWT) identifier.
 */
@Immutable
public final class JWTID extends Identifier {


	/**
	 * Creates a new JWT identifier with the specified value.
	 *
	 * @param value The JWT identifier value. Must not be {@code null} or
	 *              empty string.
	 */
	public JWTID(final String value) {

		super(value);
	}


	/**
	 * Creates a new JWT identifier with a randomly generated value of the 
	 * specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public JWTID(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new JWT identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public JWTID() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof JWTID &&
		       this.toString().equals(object.toString());
	}
}