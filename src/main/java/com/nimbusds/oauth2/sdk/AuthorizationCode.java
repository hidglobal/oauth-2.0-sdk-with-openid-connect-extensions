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
 *
 * @author Vladimir Dzhuvinov
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
	 * the specified length. The value will be made up of mixed-case 
	 * alphanumeric ASCII characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public AuthorizationCode(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new authorisation code with a randomly generated value. 
	 * The value will be made up of 32 mixed-case alphanumeric ASCII 
	 * characters.
	 */
	public AuthorizationCode() {

		super();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof AuthorizationCode && 
		       this.toString().equals(object.toString());
	}
}
