package com.nimbusds.openid.connect.sdk.messages;


import java.net.URL;

import java.util.Set;


/**
 * Client update request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-17)
 */
public class ClientUpdateRequest extends ClientRegistrationRequest {


	/**
	 * Creates a new client update request.
	 *
	 * @param redirectURIs The client redirect URIs. The set must not be
	 *                     {@code null} and must include at least one URL.
	 */
	public ClientUpdateRequest(final Set<URL> redirectURIs) {

		super(ClientRegistrationType.CLIENT_UPDATE, redirectURIs);
	}


	/**
	 * Creates a new client update request.
	 *
	 * @param redirectURI The client redirect URI. Must not be 
	 *                    {@code null}.
	 */
	public ClientUpdateRequest(final URL redirectURI) {

		super(ClientRegistrationType.CLIENT_UPDATE, redirectURI);
	}
}