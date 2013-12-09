package com.nimbusds.oauth2.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation code. A maximum authorization code lifetime of 10 minutes is 
 * recommended. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.3.1.
 * </ul>
 */
@Immutable
public final class AuthorizationCode extends Identifier {


	/**
	 * Creates a new authorisation code with the specified value.
	 *
	 * @param value The code value. Must not be {@code null} or empty 
	 *              string.
	 */
	public AuthorizationCode(final String value) {
	
		super(value);
	}


	/**
	 * Creates a new authorisation code with a randomly generated value of 
	 * the specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public AuthorizationCode(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new authorisation code with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public AuthorizationCode() {

		super();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AuthorizationCode &&
		       this.toString().equals(object.toString());
	}
}
