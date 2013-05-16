package com.nimbusds.oauth2.sdk;


import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Refresh token request to the Token endpoint. Used to refresh an 
 * {@link com.nimbusds.oauth2.sdk.token.AccessToken access token}. This class 
 * is immutable.
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
 * grant_type=refresh_token&amp;refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 6.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class RefreshTokenRequest extends TokenRequest {


	/**
	 * The refresh token.
	 */
	private final RefreshToken refreshToken;
	
	
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
	public RefreshTokenRequest(final RefreshToken refreshToken, 
		                   final ClientAuthentication clientAuth) {
	
		super(GrantType.REFRESH_TOKEN, clientAuth);
		
		if (refreshToken == null)
			throw new IllegalArgumentException("The refresh token must not be null");
		
		this.refreshToken = refreshToken;
	}
	
	
	/**
	 * Gets the refresh token.
	 *
	 * @return The refresh token.
	 */
	public RefreshToken getRefreshToken() {
	
		return refreshToken;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest(final URL url)
		throws SerializeException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);
		
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		Map<String,String> params = new LinkedHashMap<String,String>();
		params.put("grant_type", getGrantType().toString());
		params.put("refresh_token", refreshToken.getValue());
		
		httpRequest.setQuery(URLUtils.serializeParameters(params));
		
		if (getClientAuthentication() != null)
			getClientAuthentication().applyTo(httpRequest);
		
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
	 *                        refresh token request.
	 */
	public static RefreshTokenRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		// No fragment!
		// May use query component!
		
		Map<String,String> params = httpRequest.getQueryParameters();
		
		
		// Parse grant type
		String grantTypeString = params.get("grant_type");
		
		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter");

		GrantType grantType = new GrantType(grantTypeString);
			
		if (! grantType.equals(GrantType.REFRESH_TOKEN))
			throw new ParseException("Invalid \"grant_type\" parameter: " + grantTypeString);
		
		
		// Parse refresh token
		String tokenString = params.get("refresh_token");
		
		if (tokenString == null)
			throw new ParseException("Missing \"refresh_token\" parameter");
		
		// Parse client authentication
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);
		
		return new RefreshTokenRequest(new RefreshToken(tokenString), clientAuth);
	}
}
