package com.nimbusds.openid.connect.sdk.messages;


import java.net.URL;

import java.util.Set;

import com.nimbusds.openid.connect.sdk.ParseException;

import com.nimbusds.openid.connect.sdk.http.HTTPRequest;


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
 * @version $version$ (2013-01-11)
 */
public class ClientUpdateRequest extends ClientDetailsRequest {


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


	/**
	 * Parses a client update request from the specified HTTP POST
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The parsed client update request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        valid client update request.
	 */
	public static ClientUpdateRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		ClientDetailsRequest req = ClientDetailsRequest.parse(httpRequest);

		if (req instanceof ClientUpdateRequest)
			return (ClientUpdateRequest)req;

		else
			throw new ParseException("Invalid \"type\" parameter", ErrorCode.INVALID_TYPE);
	}
}