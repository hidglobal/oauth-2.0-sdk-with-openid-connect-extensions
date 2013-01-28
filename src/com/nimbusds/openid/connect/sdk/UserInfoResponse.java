package com.nimbusds.openid.connect.sdk;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.OAuth2Response;
import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * UserInfo endpoint response. This is the base abstract class for UserInfo
 * success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.3.3.
 *     <li>OpenID Connect Standard 1.0, section 4.3.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-28)
 */
public abstract class UserInfoResponse implements OAuth2Response {


	/**
	 * Parses a UserInfo response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The UserInfo success or error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        UserInfo response.
	 */
	public static UserInfoResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK)
			return UserInfoSuccessResponse.parse(httpResponse);
		else
			return UserInfoErrorResponse.parse(httpResponse);
	}
}