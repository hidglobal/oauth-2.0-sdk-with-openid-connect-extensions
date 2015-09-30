package com.nimbusds.oauth2.sdk.auth.verifier;


import com.nimbusds.jose.proc.SecurityContext;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.ClientID;
import net.jcip.annotations.ThreadSafe;


/**
 * Client authentication context.
 */
@ThreadSafe
public class ClientAuthenticationContext<T> implements SecurityContext {


	/**
	 * The claimed (unverified) client ID.
	 */
	private final ClientID claimedClientID;


	/**
	 * The client authentication method.
	 */
	private final ClientAuthenticationMethod authMethod;


	/**
	 * Optional data.
	 */
	private T data;


	/**
	 * Creates a new JWT authentication verifier context.
	 *
	 * @param claimedClientID The claimed (unverified) client ID. Must not
	 *                        be {@code null}.
	 * @param authMethod      The client authentication method. Must be
	 *                        client_secret_jwt or private_key_jwt.
	 */
	public ClientAuthenticationContext(final ClientID claimedClientID,
					   final ClientAuthenticationMethod authMethod) {

		if (claimedClientID == null) {
			throw new IllegalArgumentException("The claimed client ID must not be null");
		}

		this.claimedClientID = claimedClientID;

		if (authMethod == null) {
			throw new IllegalArgumentException("The client authentication method must not be null");
		}

		this.authMethod = authMethod;
	}


	/**
	 * Returns the claimed client ID.
	 *
	 * @return The client ID.
	 */
	public ClientID getClaimedClientID() {

		return claimedClientID;
	}


	/**
	 * Returns the client authentication method.
	 *
	 * @return The client authentication method.
	 */
	public ClientAuthenticationMethod getClientAuthenticationMethod() {

		return authMethod;
	}


	public void setData(final T data) {

		this.data = data;
	}


	public T getData() {

		return data;
	}


	/**
	 * Determines the context of the specified client authentication.
	 *
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 */
	public ClientAuthenticationContext(final ClientAuthentication clientAuth)
		throws InvalidClientException {

		authMethod = clientAuth.getMethod();
		claimedClientID = clientAuth.getClientID();
	}
}
