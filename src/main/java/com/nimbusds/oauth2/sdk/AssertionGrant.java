package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.id.ClientID;


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
	 * Optional client identifier.
	 */
	private final ClientID clientID;


	/**
	 * Creates a new assertion-based authorisation grant.
	 *
	 * @param type     The authorisation grant type. Must not be
	 *                 {@code null}.
	 * @param clientID The client identifier, if required for the
	 *                 particular client authentication method employed,
	 *                 else {@code null}.
	 */
	protected AssertionGrant(final GrantType type, final ClientID clientID) {

		super(type);

		this.clientID = clientID;
	}


	/**
	 * Gets the assertion.
	 *
	 * @return The assertion as a string.
	 */
	public abstract String getAssertion();


	/**
	 * Gets the optional client identifier.
	 *
	 * @return The client identifier, {@code null} if not specified.
	 */
	public ClientID getClientID() {

		return clientID;
	}
}
