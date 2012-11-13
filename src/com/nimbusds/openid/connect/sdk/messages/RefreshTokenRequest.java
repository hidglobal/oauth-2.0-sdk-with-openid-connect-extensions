package com.nimbusds.openid.connect.sdk.messages;


import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.CommonContentTypes;
import com.nimbusds.openid.connect.sdk.http.HTTPRequest;

import com.nimbusds.openid.connect.sdk.util.URLUtils;


/**
 * Refresh token request to the Token endpoint. Used to refresh an 
 * {@link AccessToken access token}. This class is immutable.
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
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.2.
 *     <li>OpenID Connect Standard 1.0, section 3.2.
 *     <li>OAuth 2.0 (RFC 6749), section 6.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-13)
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
	public RefreshTokenRequest(final RefreshToken refreshToken, final ClientAuthentication clientAuth) {
	
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
	
	
	/**
	 * Returns the HTTP request for this refresh token request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If this refresh token request couldn't be 
	 *                            serialised to an HTTP request.
	 */
	@Override
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
		
		Map<String,String> params = httpRequest.getQueryParameters();
		
		
		// Parse grant type
		final String grantTypeString = params.get("grant_type");
		
		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter");
			
		if (! grantTypeString.equals(GrantType.REFRESH_TOKEN.toString()))
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
