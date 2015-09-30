package com.nimbusds.oauth2.sdk.auth;


import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Base abstract class for plain secret based client authentication at the
 * Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 2.3.1 and 3.2.1.
 *     <li>OpenID Connect Core 1.0, section 9.
 * </ul>
 */
public abstract class PlainClientSecret extends ClientAuthentication {


	/**
	 * The client secret.
	 */
	private final Secret secret;


	/**
	 * Creates a new plain secret based client authentication.
	 *
	 * @param method   The client authentication method. Must not be
	 *                 {@code null}.
	 * @param clientID The client identifier. Must not be {@code null}.
	 * @param secret   The client secret. Must not be {@code null}.
	 */
	protected PlainClientSecret(final ClientAuthenticationMethod method,
				    final ClientID clientID,
				    final Secret secret) {

		super(method, clientID);

		if (secret == null) {
			throw new IllegalArgumentException("The client secret must not be null");
		}

		this.secret = secret;
	}


	/**
	 * Gets the client secret.
	 *
	 * @return The client secret.
	 */
	public Secret getClientSecret() {

		return secret;
	}
}
