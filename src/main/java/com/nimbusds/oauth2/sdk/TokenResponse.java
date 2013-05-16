package com.nimbusds.oauth2.sdk;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Token endpoint response. This is the base abstract class for access token
 * (success) and token error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public abstract class TokenResponse implements Response {


	/**
	 * Parses a token response from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   @code null}.
	 *
	 * @return The access token or token error response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        token response.
	 */
	public static TokenResponse parse(JSONObject jsonObject)
		throws ParseException{

		if (jsonObject.containsKey("access_token"))
			return AccessTokenResponse.parse(jsonObject);
		else
			return TokenErrorResponse.parse(jsonObject);
	}


	/**
	 * Parses a token response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The access token or token error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        token response.
	 */
	public static TokenResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() ==  HTTPResponse.SC_OK)
			return AccessTokenResponse.parse(httpResponse);
		else
			return TokenErrorResponse.parse(httpResponse);
	}
}