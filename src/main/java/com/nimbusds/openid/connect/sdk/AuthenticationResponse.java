package com.nimbusds.openid.connect.sdk;


import java.net.URI;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * OpenID Connect authentication response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.2.5. and 3.1.2.6.
 * </ul>
 */
public interface AuthenticationResponse extends Response {


	/**
	 * Gets the base redirection URI.
	 *
	 * @return The base redirection URI (without the appended error
	 *         response parameters).
	 */
	public URI getRedirectionURI();


	/**
	 * Gets the optional state.
	 *
	 * @return The state, {@code null} if not requested.
	 */
	public State getState();
}
