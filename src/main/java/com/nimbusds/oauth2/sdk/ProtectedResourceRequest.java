package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.token.AccessToken;


/**
 * Base abstract class for protected resource requests using an OAuth 2.0
 * access token.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>RFC 6749
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
 public abstract class ProtectedResourceRequest implements Request {


 	/**
	 * OAuth 2.0 Bearer access token.
	 */
	private final AccessToken accessToken;
	
	
	/**
	 * Creates a new protected resource request.
	 * 
	 * @param accessToken An OAuth 2.0 access token for the request, 
	 *                    {@code null} if none.
	 */
	protected ProtectedResourceRequest(final AccessToken accessToken) {

		this.accessToken = accessToken;
	}


	/**
	 * Gets the OAuth 2.0 access token for this protected resource request.
	 *
	 * @return The OAuth 2.0 access token, {@code null} if none.
	 */
	public AccessToken getAccessToken() {

		return accessToken;
	}
 }