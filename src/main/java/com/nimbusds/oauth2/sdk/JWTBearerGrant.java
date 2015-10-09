package com.nimbusds.oauth2.sdk;


import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;


/**
 * JWT bearer grant. Used in access token requests with a JSON Web Token (JWT),
 * such an OpenID Connect ID token.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523), section-2.1.
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521), section 4.1.
 * </ul>
 */
@Immutable
public class JWTBearerGrant extends AssertionGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.JWT_BEARER;


	/**
	 * The JWT assertion.
	 */
	private final SignedJWT assertion;


	/**
	 * Creates a new JSON Web Token (JWT) bearer assertion grant.
	 *
	 * @param assertion The signed JSON Web Token (JWT) assertion. Must be
	 *                  in a signed or verified state and not {@code null}.
	 *                  The JWT claims are not validated for compliance
	 *                  with the standard.
	 */
	public JWTBearerGrant(final SignedJWT assertion) {

		super(GRANT_TYPE);

		if (assertion.getState().equals(JWSObject.State.UNSIGNED))
			throw new IllegalArgumentException("The JWT assertion must not be in a unsigned state");

		this.assertion = assertion;
	}


	/**
	 * Gets the JSON Web Token (JWT) bearer assertion.
	 *
	 * @return The JWT bearer assertion.
	 */
	public SignedJWT getJWTAssertion() {

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
		return params;
	}


	/**
	 * Parses a JWT bearer grant from the specified parameters. The JWT
	 * claims are not validated for compliance with the standard.
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

		if (! GrantType.parse(grantTypeString).equals(GRANT_TYPE))
			throw new ParseException("The \"grant_type\" must be " + GRANT_TYPE, OAuth2Error.UNSUPPORTED_GRANT_TYPE);

		// Parse JWT assertion
		String assertionString = params.get("assertion");

		if (assertionString == null || assertionString.trim().isEmpty())
			throw new ParseException("Missing or empty \"assertion\" parameter", OAuth2Error.INVALID_REQUEST);

		final SignedJWT assertion;

		try {
			assertion = SignedJWT.parse(assertionString);
		} catch (java.text.ParseException e) {
			throw new ParseException("The \"assertion\" is not a signed JWT: " + e.getMessage(), OAuth2Error.INVALID_REQUEST, e);
		}

		return new JWTBearerGrant(assertion);
	}
}
