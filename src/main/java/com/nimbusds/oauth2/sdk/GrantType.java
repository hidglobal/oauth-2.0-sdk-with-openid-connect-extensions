package com.nimbusds.oauth2.sdk;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation grant type.
 */
@Immutable
public final class GrantType extends Identifier {

	
	/**
	 * Authorisation code. Client authentication required only for
	 * confidential clients.
	 */
	public static final GrantType AUTHORIZATION_CODE = new GrantType("authorization_code", false, true, new HashSet<>(Arrays.asList("code", "redirect_uri", "code_verifier")));


	/**
	 * Implicit. Client authentication is not performed (except for signed
	 * OpenID Connect authentication requests).
	 */
	public static final GrantType IMPLICIT = new GrantType("implicit", false, true, Collections.<String>emptySet());
	
	
	/**
	 * Refresh token. Client authentication required only for confidential
	 * clients.
	 */
	public static final GrantType REFRESH_TOKEN = new GrantType("refresh_token", false, false, Collections.singleton("refresh_token"));


	/**
	 * Password. Client authentication required only for confidential
	 * clients.
	 */
	public static final GrantType PASSWORD = new GrantType("password", false, false, new HashSet<>(Arrays.asList("username", "password")));


	/**
	 * Client credentials. Client authentication is required.
	 */
	public static final GrantType CLIENT_CREDENTIALS = new GrantType("client_credentials", true, true, Collections.<String>emptySet());


	/**
	 * JWT bearer, as defined in RFC 7523. Explicit client authentication
	 * is optional.
	 */
	public static final GrantType JWT_BEARER = new GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer", false, false, Collections.singleton("assertion"));


	/**
	 * SAML 2.0 bearer, as defined in RFC 7522. Explicit client
	 * authentication is optional.
	 */
	public static final GrantType SAML2_BEARER = new GrantType("urn:ietf:params:oauth:grant-type:saml2-bearer", false, false, Collections.singleton("assertion"));


	/**
	 * The client authentication requirement for this grant type.
	 */
	private final boolean requiresClientAuth;


	/**
	 * The client identifier requirement for this grant type.
	 */
	private final boolean requiresClientID;


	/**
	 * The names of the token request parameters specific to this grant
	 * type.
	 */
	private final Set<String> requestParamNames;


	/**
	 * Creates a new OAuth 2.0 authorisation grant type with the specified
	 * value. The client authentication requirement is set to
	 * {@code false}. So is the client identifier requirement.
	 *
	 * @param value The authorisation grant type value. Must not be
	 *              {@code null} or empty string.
	 */
	public GrantType(final String value) {

		this(value, false, false, Collections.<String>emptySet());
	}


	/**
	 * Creates a new OAuth 2.0 authorisation grant type with the specified
	 * value.
	 *
	 * @param value              The authorisation grant type value. Must
	 *                           not be {@code null} or empty string.
	 * @param requiresClientAuth The client authentication requirement.
	 * @param requiresClientID   The client identifier requirement.
	 * @param requestParamNames  The names of the token request parameters
	 *                           specific to this grant type, empty set or
	 *                           {@code null} if none.
	 */
	private GrantType(final String value,
			  final boolean requiresClientAuth,
			  final boolean requiresClientID,
			  final Set<String> requestParamNames) {

		super(value);
		this.requiresClientAuth = requiresClientAuth;
		this.requiresClientID = requiresClientID;
		this.requestParamNames = requestParamNames == null ? Collections.<String>emptySet() : Collections.unmodifiableSet(requestParamNames);
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
	 *         client authentication, or as a parameter in the token
	 *         request body), else {@code false}.
	 */
	public boolean requiresClientID() {

		return requiresClientID;
	}


	/**
	 * Gets the names of the token request parameters specific to this
	 * grant type.
	 *
	 * @return The parameter names, empty set if none.
	 */
	public Set<String> getRequestParameterNames() {

		return requestParamNames;
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof GrantType && this.toString().equals(object.toString());
	}


	/**
	 * Parses a grant type from the specified string.
	 *
	 * @param value The string to parse.
	 *
	 * @return The grant type.
	 *
	 * @throws ParseException If string is {@code null}, blank or empty.
	 */
	public static GrantType parse(final String value)
		throws ParseException {

		GrantType grantType;

		try {
			grantType = new GrantType(value);

		} catch (IllegalArgumentException e) {

			throw new ParseException(e.getMessage());
		}

		if (grantType.equals(GrantType.AUTHORIZATION_CODE)) {

			return GrantType.AUTHORIZATION_CODE;

		} else if (grantType.equals(GrantType.IMPLICIT)) {

			return GrantType.IMPLICIT;

		} else if (grantType.equals(GrantType.REFRESH_TOKEN)) {

			return GrantType.REFRESH_TOKEN;

		} else if (grantType.equals(GrantType.PASSWORD)) {

			return GrantType.PASSWORD;

		} else if (grantType.equals(GrantType.CLIENT_CREDENTIALS)) {

			return GrantType.CLIENT_CREDENTIALS;

		} else if (grantType.equals(GrantType.JWT_BEARER)) {

			return GrantType.JWT_BEARER;

		} else if (grantType.equals(GrantType.SAML2_BEARER)) {

			return GrantType.SAML2_BEARER;

		} else {

			return grantType;
		}
	}
}
