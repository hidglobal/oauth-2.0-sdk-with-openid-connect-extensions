package com.nimbusds.oauth2.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation response type. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 3.1.1 and 4.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
@Immutable
public final class ResponseType extends Identifier {

	
	/**
	 * Authorization code.
	 */
	public static final ResponseType CODE = new ResponseType("code");
	
	
	/**
	 * Access token, with optional refresh token.
	 */
	public static final ResponseType TOKEN = new ResponseType("token");


	/**
	 * Creates a new response type with the specified value.
	 *
	 * @param value The response type value. Must not be {@code null} or
	 *              empty string.
	 */
	public ResponseType(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof ResponseType && 
		       this.toString().equals(object.toString());
	}
}
