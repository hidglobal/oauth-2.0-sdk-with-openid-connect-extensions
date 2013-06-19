package com.nimbusds.oauth2.sdk.client;


import java.net.URL;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Client delete request. This class is immutable.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * DELETE /register/s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer reg-23410913-abewfq.123483
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-12), section 4.4.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class ClientDeleteRequest extends ProtectedResourceRequest {


	/**
	 * Creates a new client delete request.
	 *
	 * @param accessToken An OAuth 2.0 Bearer access token for the request, 
	 *                    {@code null} if none.
	 */
	public ClientDeleteRequest(final BearerAccessToken accessToken) {

		super(accessToken);
		
		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");
	}


	@Override
	public HTTPRequest toHTTPRequest(final URL url) {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.DELETE, url);
		httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
		return httpRequest;
	}


	/**
	 * Parses a client delete request from the specified HTTP DELETE 
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client add (register) request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client delete request.
	 */
	public static ClientDeleteRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.DELETE);
		
		// Parse the bearer access token
		String authzHeaderValue = httpRequest.getAuthorization();
		
		BearerAccessToken accessToken = BearerAccessToken.parse(authzHeaderValue);
		
		return new ClientDeleteRequest(accessToken);
	}
}