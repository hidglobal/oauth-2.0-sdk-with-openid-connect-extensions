package com.nimbusds.oauth2.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation grant type. This class is immutable.
 */
@Immutable
public final class GrantType extends Identifier {

	
	/**
	 * Authorisation code.
	 */
	public static final GrantType AUTHORIZATION_CODE = new GrantType("authorization_code");


	/**
	 * Implicit.
	 */
	public static final GrantType IMPLICIT = new GrantType("implicit");
	
	
	/**
	 * Refresh token.
	 */
	public static final GrantType REFRESH_TOKEN = new GrantType("refresh_token");


	/**
	 * Password.
	 */
	public static final GrantType PASSWORD = new GrantType("password");


	/**
	 * Client credentials.
	 */
	public static final GrantType CLIENT_CREDENTIALS = new GrantType("client_credentials");


	/**
	 * Creates a new OAuth 2.0 authorisation grant type with the specified
	 * value.
	 *
	 * @param value The authorisation grant type value. Must not be
	 *              {@code null} or empty string.
	 */
	public GrantType(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof GrantType &&
		       this.toString().equals(object.toString());
	}
}
