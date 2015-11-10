package com.nimbusds.oauth2.sdk;


import java.util.*;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;


/**
 * JWT bearer grant. Used in access token requests with a JSON Web Token (JWT),
 * such an OpenID Connect ID token.
 *
 * <p>The JWT assertion can be:
 *
 * <ul>
 *     <li>Signed or MAC protected with JWS
 *     <li>Encrypted with JWE
 *     <li>Nested - signed / MAC protected with JWS and then encrypted with JWE
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521), section 4.1.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523), section-2.1.
 * </ul>
 */
@Immutable
public class JWTBearerGrant extends AssertionGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.JWT_BEARER;


	/**
	 * The assertion - signed JWT, encrypted JWT or nested signed+encrypted
	 * JWT.
	 */
	private final JOSEObject assertion;


	/**
	 * Creates a new signed JSON Web Token (JWT) bearer assertion grant.
	 *
	 * @param assertion The signed JSON Web Token (JWT) assertion. Must not
	 *                  be in a unsigned state or {@code null}. The JWT
	 *                  claims are not validated for compliance with the
	 *                  standard.
	 */
	public JWTBearerGrant(final SignedJWT assertion) {

		super(GRANT_TYPE);

		if (assertion.getState().equals(JWSObject.State.UNSIGNED))
			throw new IllegalArgumentException("The JWT assertion must not be in a unsigned state");

		this.assertion = assertion;
	}


	/**
	 * Creates a new nested signed and encrypted JSON Web Token (JWT)
	 * bearer assertion grant.
	 *
	 * @param assertion The nested signed and encrypted JSON Web Token
	 *                  (JWT) assertion. Must not be in a unencrypted state
	 *                  or {@code null}. The JWT claims are not validated
	 *                  for compliance with the standard.
	 */
	public JWTBearerGrant(final JWEObject assertion) {

		super(GRANT_TYPE);

		if (assertion.getState().equals(JWEObject.State.UNENCRYPTED))
			throw new IllegalArgumentException("The JWT assertion must not be in a unencrypted state");

		this.assertion = assertion;
	}


	/**
	 * Creates a new signed and encrypted JSON Web Token (JWT) bearer
	 * assertion grant.
	 *
	 * @param assertion The signed and encrypted JSON Web Token (JWT)
	 *                  assertion. Must not be in a unencrypted state or
	 *                  {@code null}. The JWT claims are not validated for
	 *                  compliance with the standard.
	 */
	public JWTBearerGrant(final EncryptedJWT assertion) {

		this((JWEObject) assertion);
	}


	/**
	 * Gets the JSON Web Token (JWT) bearer assertion.
	 *
	 * @return The assertion as a signed or encrypted JWT, {@code null} if
	 *         the assertion is a signed and encrypted JWT.
	 */
	public JWT getJWTAssertion() {

		return assertion instanceof JWT ?  (JWT)assertion : null;
	}


	/**
	 * Gets the JSON Web Token (JWT) bearer assertion.
	 *
	 * @return The assertion as a generic JOSE object (signed JWT,
	 *         encrypted JWT, or signed and encrypted JWT).
	 */
	public JOSEObject getJOSEAssertion() {

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

		try {
			final JOSEObject assertion = JOSEObject.parse(assertionString);

			if (assertion instanceof PlainObject) {

				throw new ParseException("The JWT assertion must not be unsecured (plain)", OAuth2Error.INVALID_REQUEST);

			} else if (assertion instanceof JWSObject) {

				return new JWTBearerGrant(new SignedJWT(
						assertion.getParsedParts()[0],
						assertion.getParsedParts()[1],
						assertion.getParsedParts()[2]));

			} else {
				// JWE

				if ("JWT".equalsIgnoreCase(assertion.getHeader().getContentType())) {
					// Assume nested: signed JWT inside JWE
					// http://tools.ietf.org/html/rfc7519#section-5.2
					return new JWTBearerGrant((JWEObject)assertion);
				} else {
					// Assume encrypted JWT
					return new JWTBearerGrant(new EncryptedJWT(
							assertion.getParsedParts()[0],
							assertion.getParsedParts()[1],
							assertion.getParsedParts()[2],
							assertion.getParsedParts()[3],
							assertion.getParsedParts()[4]));
				}
			}

		} catch (java.text.ParseException e) {
			throw new ParseException("The \"assertion\" is not a JWT: " + e.getMessage(), OAuth2Error.INVALID_REQUEST, e);
		}
	}
}
