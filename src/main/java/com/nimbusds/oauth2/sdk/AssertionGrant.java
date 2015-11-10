package com.nimbusds.oauth2.sdk;


/**
 * Assertion grant. Used in access token requests with an assertion, such as a
 * SAML 2.0 assertion or JSON Web Token (JWT).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521), section 4.1.
 * </ul>
 */
public abstract class AssertionGrant extends AuthorizationGrant {


	/**
	 * Cached missing {@code grant_type} parameter exception.
	 */
	protected static final ParseException MISSING_GRANT_TYPE_PARAM_EXCEPTION
		= new ParseException("Missing \"grant_type\" parameter", OAuth2Error.INVALID_REQUEST);


	/**
	 * Caches missing {@code assertion} parameter exception.
	 */
	protected static final ParseException MISSING_ASSERTION_PARAM_EXCEPTION
		= new ParseException("Missing or empty \"assertion\" parameter", OAuth2Error.INVALID_REQUEST);


	/**
	 * Creates a new assertion-based authorisation grant.
	 *
	 * @param type The authorisation grant type. Must not be {@code null}.
	 */
	protected AssertionGrant(final GrantType type) {

		super(type);
	}


	/**
	 * Gets the assertion.
	 *
	 * @return The assertion as a string.
	 */
	public abstract String getAssertion();
}
