package com.nimbusds.oauth2.sdk;


import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;


/**
 * Client credentials grant. Used in access token requests with a client's
 * identifier and secret. This class is immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 4.4.2.
 * </ul>
 */
@Immutable
public class ClientCredentialsGrant extends AuthorizationGrant {


	/**
	 * The associated grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.CLIENT_CREDENTIALS;


	/**
	 * The requested scope.
	 */
	private final Scope scope;


	/**
	 * Creates a new client credentials grant.
	 *
	 * @param scope The requested scope, {@code null} if not specified.
	 */
	public ClientCredentialsGrant(final Scope scope) {

		super(GRANT_TYPE);

		this.scope = scope;
	}


	/**
	 * Gets the requested scope.
	 *
	 * @return The requested scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}


	@Override
	public Map<String,String> toParameters() {

		Map<String,String> params = new LinkedHashMap<String,String>();

		params.put("grant_type", GRANT_TYPE.getValue());

		if (scope != null)
			params.put("scope", scope.toString());

		return params;
	}


	/**
	 * Parses a client credentials grant from the specified parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=client_credentials
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The client credentials grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ClientCredentialsGrant parse(final Map<String,String> params)
		throws ParseException {

		// Parse grant type
		String grantTypeString = params.get("grant_type");

		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter", OAuth2Error.INVALID_REQUEST);

		GrantType grantType = new GrantType(grantTypeString);

		if (! grantType.equals(GRANT_TYPE))
			throw new ParseException("The \"grant_type\" must be " + GRANT_TYPE, OAuth2Error.INVALID_GRANT);

		// Parse optional scope
		String scopeValue = params.get("scope");

		Scope scope = null;

		if (scopeValue != null)
			scope = Scope.parse(scopeValue);

		return new ClientCredentialsGrant(scope);
	}
}
