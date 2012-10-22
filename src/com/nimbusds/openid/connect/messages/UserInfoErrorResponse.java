package com.nimbusds.openid.connect.messages;


import java.net.URL;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * UserInfo error response. This class is immutable.
 *
 * <p>Legal error codes:
 *
 * <ul>
 *     <li>OAuth 2.0 errors:
 *         <ul>
 *             <li>{@link ErrorCode#INVALID_REQUEST}
 *             <li>{@link ErrorCode#INVALID_TOKEN}
 *             <li>{@link ErrorCode#INSUFFICIENT_SCOPE}
 *         </ul>
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: Bearer realm="example.com",
 *                   error="invalid_token",
 *                   error_description="The access token expired"
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.3.3.
 *     <li>OpenID Connect Standard 1.0, section 4.3.
 *     <li>The OAuth 2.0 Authorization Framework: Bearer Token Usage
 *         (draft-ietf-oauth-v2-bearer-23), section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-22)
 */
public final class UserInfoErrorResponse extends OAuthBearerTokenErrorResponse {


	/**
	 * Creates a new UserInfo error response.
	 *
	 * @param realm     The bearer realm. May be {@code null}.
	 * @param errorCode The error code. Must match one of the legal error 
	 *                  codes for an OAuth 2.0 Bear Token error response. It
	 *                  may be {@code null} if the client didn't provide any 
	 *                  authentication information in the original request.
	 * @param errorURI  Optional URI of a web page that includes information
	 *                  about the error, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the specified error code is not
	 *                                  legal for an OAuth 2.0 Bear Token
	 *                                  error response.
	 */
	public UserInfoErrorResponse(final String realm, 
	                             final ErrorCode errorCode,
				     final URL errorURI) {
				    
		super(realm, errorCode, errorURI);
	}
	
	
	/**
	 * Parses a UserInfo error response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @throws ParseException If the HTTP response cannot be parsed to a 
	 *                        valid UserInfo error response.
	 */
	public static UserInfoErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		OAuthBearerTokenErrorResponse r = OAuthBearerTokenErrorResponse.parse(httpResponse);
		
		return new UserInfoErrorResponse(r.getRealm(), r.getErrorCode(), r.getErrorURI());
	}
}
