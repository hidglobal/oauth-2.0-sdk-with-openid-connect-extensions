package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import java.util.Set;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.token.AccessToken;


/**
 * OpenID Connect client update request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-25)
 */
public class ClientUpdateRequest extends ClientDetailsRequest {


	/**
	 * Creates a new OpenID Connect client update request.
	 *
	 * @param accessToken  The OAuth 2.0 access token. Must not be 
	 *                     {@code null}.
	 * @param redirectURIs The client redirect URIs. The set must not be
	 *                     {@code null} and must include at least one URL.
	 */
	public ClientUpdateRequest(final AccessToken accessToken, final Set<URL> redirectURIs) {

		super(ClientRegistrationOperation.CLIENT_UPDATE, redirectURIs);

		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");

		setAccessToken(accessToken);
	}


	/**
	 * Creates a new OpenID Connect client update request.
	 *
	 * @param accessToken The OAuth 2.0 access token. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The client redirect URI. Must not be 
	 *                    {@code null}.
	 */
	public ClientUpdateRequest(final AccessToken accessToken, final URL redirectURI) {

		super(ClientRegistrationOperation.CLIENT_UPDATE, redirectURI);

		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");

		setAccessToken(accessToken);
	}


	/**
	 * Parses an OpenID Connect client update request from the specified
	 * HTTP POST request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client update request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client update request.
	 */
	public static ClientUpdateRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		ClientDetailsRequest detReq = ClientDetailsRequest.parse(httpRequest);

		if (detReq.getOperation() != ClientRegistrationOperation.CLIENT_UPDATE)
			throw new ParseException("Invalid \"operation\" parameter", 
					         OIDCError.INVALID_OPERATION);
	
		AccessToken accessToken = detReq.getAccessToken();

		if (accessToken == null)
			throw new ParseException("Missing access token");

		ClientUpdateRequest req = new ClientUpdateRequest(accessToken, detReq.getRedirectURIs());

		req.applyOptionalParameters(detReq.toParameters(true));

		return req;
	}
}
