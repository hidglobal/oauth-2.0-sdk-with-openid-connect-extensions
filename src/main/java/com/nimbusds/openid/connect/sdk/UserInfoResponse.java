package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * The base abstract class for UserInfo success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.3.2 and 5.3.3.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 */
public abstract class UserInfoResponse implements Response {


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