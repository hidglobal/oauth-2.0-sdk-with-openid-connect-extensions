package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import java.net.URL;

import org.apache.commons.lang3.StringUtils;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * OpenID Connect client read request. This class is immutable.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * GET /connect/register?client_id=s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer this.is.an.access.token.value.ffx83
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 4.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class OIDCClientReadRequest extends ProtectedResourceRequest {


	/**
	 * Creates a new OpenID Connect client read request.
	 *
	 * @param accessToken An OAuth 2.0 Bearer access token for the request. 
	 *                    Must not be {@code null}.
	 */
	public OIDCClientReadRequest(final BearerAccessToken accessToken) {

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
	 * Parses an OpenID Connect client read request from the specified HTTP
	 * GET request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client read request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client read request.
	 */
	public static OIDCClientReadRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.GET);

		String authzHeaderValue = httpRequest.getAuthorization();
		
		if (StringUtils.isBlank(authzHeaderValue))
			throw new ParseException("Missing HTTP Authorization header");
		
		BearerAccessToken accessToken = BearerAccessToken.parse(authzHeaderValue);
		
		return new OIDCClientReadRequest(accessToken);
	}
}
