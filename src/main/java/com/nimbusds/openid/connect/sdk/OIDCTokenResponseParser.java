package com.nimbusds.openid.connect.sdk;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Parser of OpenID Connect token endpoint response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, sections 2.2.3 and 2.2.4.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCTokenResponseParser { 


	/**
	 * Parses an OpenID Connect access token response or token error
	 * response from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect access token response or token error
	 * response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect token response.
	 */
	public static OIDCTokenResponse parse(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("error"))
			return OIDCTokenErrorResponse.parse(jsonObject);
		else
			return OIDCAccessTokenResponse.parse(jsonObject);
	}


	/**
	 * Parses an OpenID Connect access token response or token error
	 * response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The OpenID Connect access token response or token error
	 * response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect token response.
	 */
	public static OIDCTokenResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK)
			return OIDCAccessTokenResponse.parse(httpResponse);
		else
			return OIDCTokenErrorResponse.parse(httpResponse);
	}


	/**
	 * Prevents public instantiation.
	 */
	private OIDCTokenResponseParser() { }
}
