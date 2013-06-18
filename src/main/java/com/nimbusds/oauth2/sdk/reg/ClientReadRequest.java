package com.nimbusds.oauth2.sdk.reg;


import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import java.net.URL;

import org.apache.commons.lang3.StringUtils;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Client read request. This class is immutable.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * GET /register/s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer reg-23410913-abewfq.123483
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-12), section 4.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class ClientReadRequest extends ProtectedResourceRequest {


	/**
	 * Creates a new client read request.
	 *
	 * @param accessToken An OAuth 2.0 Bearer access token for the request. 
	 *                    Must not be {@code null}.
	 */
	public ClientReadRequest(final BearerAccessToken accessToken) {

		super(accessToken);

		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");
	}


	@Override
	public HTTPRequest toHTTPRequest(final URL url) {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, url);
		httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
		return httpRequest;
	}


	/**
	 * Parses a client read request from the specified HTTP GET request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client read request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client read request.
	 */
	public static ClientReadRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.GET);

		String authzHeaderValue = httpRequest.getAuthorization();
		
		if (StringUtils.isBlank(authzHeaderValue))
			throw new ParseException("Missing HTTP Authorization header");
		
		BearerAccessToken accessToken = BearerAccessToken.parse(authzHeaderValue);
		
		return new ClientReadRequest(accessToken);
	}
}
