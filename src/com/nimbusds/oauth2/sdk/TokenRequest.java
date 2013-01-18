package com.nimbusds.oauth2.sdk;


import java.util.Map;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * The base abstract class for access token and refresh token requests to the
 * Token endpoint. The request type can be inferred by calling 
 * {@link #getGrantType}.
 *
 * <p>Example access token request:
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 * 
 * grant_type=authorization_code
 * &amp;code=SplxlOBeZQQYbYS6WxSbIA
 * &amp;redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.3, .
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-16)
 */
public abstract class TokenRequest implements OAuth2Request {


	/**
	 * The grant type.
	 */
	private final GrantType grantType;
	
	
	/**
	 * The client authentication, {@code null} if none.
	 */
	private final ClientAuthentication clientAuth;
	
	
	/**
	 * Creates a new token request.
	 *
	 * @param grantType  The grant type. Must not be {@code null}.
	 * @param clientAuth The client authentication, {@code null} if none.
	 */
	protected TokenRequest(final GrantType grantType, final ClientAuthentication clientAuth) {
	
		if (grantType == null)
			throw new IllegalArgumentException("The grant type must not be null");
		
		this.grantType = grantType;
		
		this.clientAuth = clientAuth;
	}
	
	
	/**
	 * Gets the grant type.
	 *
	 * @return The grant type.
	 */
	public GrantType getGrantType() {
	
		return grantType;
	}
	
	
	/**
	 * Gets the client authentication.
	 *
	 * @return The client authentication, {@code null} if none.
	 */
	public ClientAuthentication getClientAuthentication() {
	
		return clientAuth;
	}
	
	
	/**
	 * Parses the specified HTTP request for a token request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The token request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        token request.
	 */
	public static TokenRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		// No fragment!
		// May use query component!
		Map<String,String> params = httpRequest.getQueryParameters();
		
		
		// Parse grant type
		final String grantTypeString = params.get("grant_type");
		
		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter");
		
		GrantType grantType = new GrantType(grantTypeString);
		
		if (grantType.equals(GrantType.AUTHORIZATION_CODE))
			return AccessTokenRequest.parse(httpRequest);

		else if (grantType.equals(GrantType.REFRESH_TOKEN))
			return RefreshTokenRequest.parse(httpRequest);
		
		else
			throw new ParseException("Unsupported \"grant_type\": " + grantType);
	}
}
