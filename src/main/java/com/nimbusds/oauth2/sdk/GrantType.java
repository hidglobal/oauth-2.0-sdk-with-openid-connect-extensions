package com.nimbusds.oauth2.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation grant type.
 */
@Immutable
public final class GrantType extends Identifier {

	
	/**
	 * Authorisation code.
	 */
	public static final GrantType AUTHORIZATION_CODE = new GrantType("authorization_code", false, true);


	/**
	 * Implicit.
	 */
	public static final GrantType IMPLICIT = new GrantType("implicit", false, true);
	
	
	/**
	 * Refresh token.
	 */
	public static final GrantType REFRESH_TOKEN = new GrantType("refresh_token", true, false);


	/**
	 * Password.
	 */
	public static final GrantType PASSWORD = new GrantType("password", false, false);


	/**
	 * Client credentials.
	 */
	public static final GrantType CLIENT_CREDENTIALS = new GrantType("client_credentials", true, true);


	/**
	 * JWT bearer, as defined in draft-ietf-oauth-jwt-bearer-10.
	 */
	public static final GrantType JWT_BEARER = new GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer", true, false);


	/**
	 * The client authentication requirement for this grant type.
	 */
	private final boolean requiresClientAuth;


	/**
	 * The client identifier requirement for this grant type.
	 */
	private final boolean requiresClientID;


	/**
	 * Creates a new OAuth 2.0 authorisation grant type with the specified
	 * value.
	 *
	 * @param value              The authorisation grant type value. Must
	 *                           not be {@code null} or empty string.
	 * @param requiresClientAuth The client authentication requirement.
	 * @param requiresClientID   The client identifier requirement.
	 */
	private GrantType(final String value,
			  final boolean requiresClientAuth,
			  final boolean requiresClientID) {

		super(value);
		this.requiresClientAuth = requiresClientAuth;
		this.requiresClientID = requiresClientID;
	}


	/**
	 * Gets the client authentication requirement.
	 *
	 * @return {@code true} if explicit client authentication is always
	 *         required for this grant type, else {@code false}.
	 */
	public boolean requiresClientAuthentication() {

		return requiresClientAuth;
	}


	/**
	 * Gets the client identifier requirement.
	 *
	 * @return {@code true} if a client identifier must always be
	 *         communicated for this grant type (either as part of the
	 *         client authentication, or as a separate parameter), else
	 *         {@code false}.
	 */
	public boolean requiresClientID() {

		return requiresClientID;
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof GrantType && this.toString().equals(object.toString());
	}


	/**
	 * Parses a grant type from the specified string.
	 *
	 * @param value The string to parse. Must not be {@code null}.
	 *
	 * @return The grant type.
	 *
	 * @throws ParseException If string doesn't correspond to a valid or
	 *                        supported grant.
	 */
	public static GrantType parse(final String value)
		throws ParseException {

		if (value.equals(GrantType.AUTHORIZATION_CODE.getValue())) {

			return GrantType.AUTHORIZATION_CODE;

		} else if (value.equals(GrantType.REFRESH_TOKEN.getValue())) {

			return GrantType.REFRESH_TOKEN;

		} else if (value.equals(GrantType.PASSWORD.getValue())) {

			return GrantType.PASSWORD;

		} else if (value.equals(GrantType.CLIENT_CREDENTIALS.getValue())) {

			return GrantType.CLIENT_CREDENTIALS;

		} else if (value.equals(GrantType.JWT_BEARER.getValue())) {

			return GrantType.JWT_BEARER;

		} else {

			throw new ParseException("Unsupported grant type: " + value, OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		}
	}
}
