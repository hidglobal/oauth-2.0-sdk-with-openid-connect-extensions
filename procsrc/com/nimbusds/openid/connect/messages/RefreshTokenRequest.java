package com.nimbusds.openid.connect.messages;


import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPRequest;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Refresh token request to the Token endpoint.
 *
 * <p>Note that the optional scope parameter is not supported.
 *
 * <p>Example refresh token request:
 *
 * <pre>
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 * Content-Type: application/x-www-form-urlencoded;charset=UTF-8
 *
 * grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
 * </pre>
 *
 * <p>See draft-ietf-oauth-v2-26, section 6.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-11)
 */
public class RefreshTokenRequest extends TokenRequest {


	/**
	 * The refresh token.
	 */
	private RefreshToken refreshToken;
	
	
	/**
	 * Creates a new unauthenticated refresh token request.
	 *
	 * @param refreshToken The refresh token. Must not be {@code null}.
	 */
	public RefreshTokenRequest(final RefreshToken refreshToken) {
	
		this(refreshToken, null);
	}
	
	 
	/**
	 * Creates a new authenticated refresh token request.
	 *
	 * @param refreshToken The refresh token. Must not be {@code null}.
	 * @param clientAuth   The client authentication, {@code null} if none.
	 */
	public RefreshTokenRequest(final RefreshToken refreshToken, final ClientAuthentication clientAuth) {
	
		super(GrantType.REFRESH_TOKEN, clientAuth);
		
		if (refreshToken == null)
			throw new NullPointerException("The refresh token must not be null");
		
		this.refreshToken = refreshToken;
	}
	
	
	/**
	 * Returns the HTTP request for this refresh token request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If this refresh token request couldn't be 
	 *                            serialised to an HTTP request.
	 */
	public HTTPRequest toHTTPRequest()
		throws SerializeException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		Map<String,String> params = new LinkedHashMap<String,String>();
		params.put("grant_type", getGrantType().toString());
		params.put("refresh_token", refreshToken.toString());
		
		httpRequest.setQuery(URLUtils.serializeParameters(params));
		
		if (getClientAuthentication() != null)
			getClientAuthentication().apply(httpRequest);
		
		return httpRequest;
	}
	
	
	/**
	 * Parses the specified HTTP request for a refresh token request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The refresh token request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        valid refresh token request.
	 */
	public static RefreshTokenRequest parse(final HTTPRequest httpRequest)
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
			
		if (! grantTypeString.equals(GrantType.AUTHORIZATION_CODE.toString()))
			throw new ParseException("Invalid \"grant_type\" parameter: " + grantTypeString);
		
		
		// Parse refresh token
		final String tokenString = params.get("refresh_token");
		
		if (tokenString == null)
			throw new ParseException("Missing \"refresh_token\" parameter");
		
		// Parse client authentication
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);
		
		return new RefreshTokenRequest(new RefreshToken(tokenString), clientAuth);
	}
}