package com.nimbusds.openid.connect.sdk.messages;


import com.nimbusds.openid.connect.sdk.claims.ClientID;


/**
 * The base abstract class for client registration responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-19)
 */
public abstract class ClientRegistrationResponse implements SuccessResponse {


	/**
	 * The client ID.
	 */
	private final ClientID clientID;


	/**
	 * Creates a new client registration response.
	 *
	 * @param clientID The client ID. Must not be {@code null}.
	 */
	protected ClientRegistrationResponse(final ClientID clientID) {

		if (clientID == null)
			throw new IllegalArgumentException("The client ID must not be null");

		if (clientID.getClaimValue() == null)
			throw new IllegalArgumentException("The client ID value must be defined");

		this.clientID = clientID;
	}


	/**
	 * Gets the client ID. Corresponds to the {@code client_id} parameter.
	 *
	 * @return The client ID.
	 */
	public ClientID getClientID() {

		return clientID;
	}
}