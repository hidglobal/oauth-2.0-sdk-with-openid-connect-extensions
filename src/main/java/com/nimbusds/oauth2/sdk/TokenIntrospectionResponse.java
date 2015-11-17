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
	

	/**
	 * Parses a token introspection response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The token introspection success or error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        token introspection response.
	 */
	public static TokenIntrospectionResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
			return TokenIntrospectionSuccessResponse.parse(httpResponse);
		} else {
			return TokenIntrospectionErrorResponse.parse(httpResponse);
		}
	}
}
