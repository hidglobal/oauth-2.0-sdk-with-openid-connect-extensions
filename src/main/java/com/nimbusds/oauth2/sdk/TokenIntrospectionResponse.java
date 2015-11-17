package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Token introspection response. This is the base abstract class for token
 * introspection success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Introspection (RFC 7662).
 * </ul>
 */
public abstract class TokenIntrospectionResponse implements Response {
	

	public static TokenIntrospectionResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
			return TokenIntrospectionSuccessResponse.parse(httpResponse);
		} else {
			return null; // TODO
		}
	}
}
