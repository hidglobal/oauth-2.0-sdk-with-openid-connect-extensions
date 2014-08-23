package com.nimbusds.oauth2.sdk;


/**
 * Assertion grant. Used in access token requests with an assertion, such as a
 * SAML 2.0 assertion or JSON Web Token (JWT).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (draft-ietf-oauth-assertions-16), section 4.1.
 * </ul>
 */
public abstract class AssertionGrant extends AuthorizationGrant {


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
