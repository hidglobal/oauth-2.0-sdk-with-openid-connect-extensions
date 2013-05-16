package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Request;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * The base abstract class for OpenID Connect client registration requests.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, sections 3.1 and 
 *         4.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
 public abstract class OIDCClientRegistrationRequest implements Request {


 	/**
	 * OAuth 2.0 Bearer access token (conditionally required).
	 */
	private BearerAccessToken accessToken = null;


	/**
	 * Gets the OAuth 2.0 Bearer access token.
	 *
	 * @return The OAuth 2.0 Bearer access token, {@code null} if none.
	 */
	public BearerAccessToken getAccessToken() {

		return accessToken;
	}


	/**
	 * Sets the OAuth 2.0 Bearer access token.
	 *
	 * @param accessToken The OAuth 2.0 Bearer access token, {@code null} 
	 *                    if none.
	 */
	public void setAccessToken(final BearerAccessToken accessToken) {

		this.accessToken = accessToken;
	}


	/**
	 * Parses an OpenID Connect client registration request from the 
	 * specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client registration request.
	 */
	public static OIDCClientRegistrationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		if (httpRequest.getMethod() == HTTPRequest.Method.POST)
			return OIDCClientAddRequest.parse(httpRequest);
		else
			return OIDCClientReadRequest.parse(httpRequest);
	}
 }