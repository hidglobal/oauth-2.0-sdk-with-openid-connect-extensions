package com.nimbusds.oauth2.sdk;


import java.net.URI;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;


/**
 * Abstract request with optional client authentication.
 *
 * <p>Client authentication methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretBasic client_secret_basic}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretPost client_secret_post}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.ClientSecretJWT client_secret_jwt}
 *     <li>{@link com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT private_key_jwt}
 * </ul>
 */
public abstract class AbstractOptionallyAuthenticatedRequest extends AbstractRequest {
	

	/**
	 * The client authentication, {@code null} if none.
	 */
	private final ClientAuthentication clientAuth;


	/**
	 * Creates a new abstract request with optional client authentication.
	 *
	 * @param uri        The URI of the endpoint (HTTP or HTTPS) for which
	 *                   the request is intended, {@code null} if not
	 *                   specified (if, for example, the
	 *                   {@link #toHTTPRequest()} method will not be used).
	 * @param clientAuth The client authentication, {@code null} if none.
	 */
	public AbstractOptionallyAuthenticatedRequest(final URI uri,
						      final ClientAuthentication clientAuth) {

		super(uri);

		this.clientAuth = clientAuth;
	}


	/**
	 * Returns the client authentication.
	 *
	 * @return The client authentication, {@code null} if none.
	 */
	public ClientAuthentication getClientAuthentication() {

		return clientAuth;
	}
}
