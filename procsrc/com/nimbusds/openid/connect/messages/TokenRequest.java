package com.nimbusds.openid.connect.messages;


import java.util.Map;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPRequest;

import com.nimbusds.openid.connect.util.URLUtils;


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
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 * Content-Type: application/x-www-form-urlencoded;charset=UTF-8
 *
 * grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
 * &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
 * </pre>
 *
 * <p>See draft-ietf-oauth-v2-26
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-11)
 */
public abstract class TokenRequest implements Request {


	/**
	 * The grant type.
	 */
	private GrantType grantType;
	
	
	/**
	 * The client authentication, {@code null} if none.
	 */
	private ClientAuthentication clientAuth;
	
	
	/**
	 * Creates a new token request.
	 *
	 * @param grantType  The grant type. Must not be {@code null}.
	 * @param clientAuth The client authentication, {@code null} if none.
	 */
	protected TokenRequest(final GrantType grantType, final ClientAuthentication clientAuth) {
	
		if (grantType == null)
			throw new NullPointerException("The grant type must not be null");
		
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
	 *                        valid token request.
	 */
	public static TokenRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		// No fragment!
		// May use query component!
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing HTTP POST request entity body");
		
		Map<String,String> params = URLUtils.parseParameters(query);
		
		
		// Parse grant type
		final String grantTypeString = params.get("grant_type");
		
		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter");
		
		GrantType grantType = GrantType.parse(grantTypeString);
		
		switch (grantType) {
		
			case AUTHORIZATION_CODE:
				return AccessTokenRequest.parse(httpRequest);
			
			case REFRESH_TOKEN:
				return RefreshTokenRequest.parse(httpRequest);
			
			default:
				throw new ParseException("Unsupported \"grant_type\": " + grantType);
		}
	}
}
