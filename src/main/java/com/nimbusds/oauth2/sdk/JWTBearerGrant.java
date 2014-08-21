package com.nimbusds.oauth2.sdk;


import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * JWT bearer grant. Used in access token requests with a JSON Web Token (JWT),
 * such an OpenID Connect ID token.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (draft-ietf-oauth-jwt-bearer-10), section-2.1.
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (draft-ietf-oauth-assertions-16), section 4.1.
 * </ul>
 */
@Immutable
public class JWTBearerGrant extends AssertionGrant {


	/**
	 * The associated grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.JWT_BEARER;


	/**
	 * The JWT assertion.
	 */
	private final JWT assertion;


	/**
	 * Creates a new JSON Web Token (JWT) assertion grant.
	 *
	 * @param assertion The JSON Web Token (JWT) assertion. Must not be
	 *                  {@code null}.
	 * @param clientID  The client identifier, if required for the
	 *                  particular client authentication method employed,
	 *                  else {@code null}.
	 */
	public JWTBearerGrant(final JWT assertion, final ClientID clientID) {

		super(GRANT_TYPE, clientID);

		if (assertion == null)
			throw new IllegalArgumentException("The JWT assertion must not be null");

		this.assertion = assertion;
	}


	/**
	 * Creates a new JSON Web Token (JWT) assertion grant.
	 *
	 * @param assertion The JSON Web Token (JWT) assertion. Must not be
	 *                  {@code null}.
	 */
	public JWTBearerGrant(final JWT assertion) {

		this(assertion, null);
	}


	/**
	 * Gets the JSON Web Token (JWT) assertion.
	 *
	 * @return The JWT assertion.
	 */
	public JWT getJWTAssertion() {

		return assertion;
	}


	@Override
	public String getAssertion() {

		return assertion.serialize();
	}


	@Override
	public Map<String,String> toParameters() {

		Map<String,String> params = new LinkedHashMap<>();
		params.put("grant_type", GRANT_TYPE.getValue());
		params.put("assertion", assertion.serialize());

		if (getClientID() != null)
			params.put("client_id", getClientID().getValue());

		return params;
	}


	/**
	 * Parses a JWT bearer grant from the specified parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
	 * &assertion=eyJhbGciOiJFUzI1NiJ9.eyJpc3Mi[...omitted for brevity...].
	 * J9l-ZhwP[...omitted for brevity...]
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The JWT bearer grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static JWTBearerGrant parse(final Map<String,String> params)
		throws ParseException {

		// Parse grant type
		String grantTypeString = params.get("grant_type");

		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter", OAuth2Error.INVALID_REQUEST);

		GrantType grantType = new GrantType(grantTypeString);

		if (! grantType.equals(GRANT_TYPE))
			throw new ParseException("The \"grant_type\" must be " + GRANT_TYPE, OAuth2Error.UNSUPPORTED_GRANT_TYPE);

		// Parse JWT assertion
		String assertionString = params.get("assertion");

		if (assertionString == null || assertionString.trim().isEmpty())
			throw new ParseException("Missing or empty \"assertion\" parameter", OAuth2Error.INVALID_REQUEST);

		JWT assertion;

		try {
			assertion = JWTParser.parse(assertionString);
		} catch (java.text.ParseException e) {
			throw new ParseException("The \"assertion\" is not a JWT: " + e.getMessage(), OAuth2Error.INVALID_REQUEST, e);
		}

		// Parse optional client ID
		String clientIDString = params.get("client_id");

		ClientID clientID = null;

		if (clientIDString != null && clientIDString.trim().length() > 0)
			clientID = new ClientID(clientIDString);

		return new JWTBearerGrant(assertion, clientID);
	}
}
